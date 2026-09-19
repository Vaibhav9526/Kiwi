//! Streaming capture reader.
//!
//! [`PcapReader`] walks classic pcap records and pcapng blocks
//! incrementally over a byte slice: bounds fire before allocation, and the
//! file-size bound is enforced as bytes are consumed (so huge files still
//! open cheaply and fail only when actually over-read).
//!
//! Every byte access goes through [`get`] helpers — direct indexing and
//! slicing never appear here, per the crate's `indexing_slicing` deny.

use super::{CaptureError, CaptureFormat, CaptureLimits, LinkType, Packet, Timestamp};

/// Detected section endianness (pcapng; classic stores it in the format).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, w: [u8; 2]) -> u16 {
        match self {
            Endian::Little => u16::from_le_bytes(w),
            Endian::Big => u16::from_be_bytes(w),
        }
    }

    fn u32(self, w: [u8; 4]) -> u32 {
        match self {
            Endian::Little => u32::from_le_bytes(w),
            Endian::Big => u32::from_be_bytes(w),
        }
    }

    /// Combine two 32-bit words (hi, lo) into one 64-bit timestamp.
    fn u64_words(self, hi: [u8; 4], lo: [u8; 4]) -> u64 {
        (u64::from(self.u32(hi)) << 32) | u64::from(self.u32(lo))
    }
}

/// Copy out exactly 2 bytes or `None`.
fn get2(bytes: &[u8], at: usize) -> Option<[u8; 2]> {
    Some([*bytes.get(at)?, *bytes.get(at + 1)?])
}

/// Copy out exactly 4 bytes or `None`.
fn get4(bytes: &[u8], at: usize) -> Option<[u8; 4]> {
    Some([
        *bytes.get(at)?,
        *bytes.get(at + 1)?,
        *bytes.get(at + 2)?,
        *bytes.get(at + 3)?,
    ])
}

/// Borrow `len` bytes or `None`.
fn getn(bytes: &[u8], at: usize, len: usize) -> Option<&[u8]> {
    let end = at.checked_add(len)?;
    bytes.get(at..end)
}

/// Streaming reader over one capture file.
#[derive(Debug)]
pub struct PcapReader<'a> {
    bytes: &'a [u8],
    limits: CaptureLimits,
    format: CaptureFormat,
    /// Classic endianness (from global magic).
    little: bool,
    /// First link type seen (global header or first IDB).
    link: Option<LinkType>,
    /// Next unread offset.
    offset: usize,
    /// Frames returned so far (1-based numbering for the next packet).
    returned: u64,
    /// pcapng: current section endianness.
    ng_endian: Endian,
    /// pcapng: per-interface tick divisors (ticks per second).
    ng_tick_hz: Vec<u64>,
}

impl<'a> PcapReader<'a> {
    /// Open a capture: validate the global/section header eagerly, read
    /// packets lazily. Huge files open cheaply; bounds fire on read.
    pub fn from_slice(bytes: &'a [u8], limits: CaptureLimits) -> Result<Self, CaptureError> {
        if is_pcapng_magic(bytes) {
            Self::open_ng(bytes, limits)
        } else {
            Self::open_classic(bytes, limits)
        }
    }

    /// Detected container format.
    pub fn format(&self) -> CaptureFormat {
        self.format
    }

    /// First link type seen, when the header carried one.
    pub fn link_type(&self) -> Option<LinkType> {
        self.link
    }

    /// Read the next packet; `Ok(None)` at clean EOF.
    ///
    /// Packet *count* is not capped here: `max_packets` bounds a single
    /// [`Self::read_packets`] batch, while the file-bytes bound always
    /// applies, so unbounded iteration still terminates.
    pub fn next_packet(&mut self) -> Result<Option<Packet>, CaptureError> {
        if self.offset > self.limits.max_file_bytes {
            return Err(CaptureError::LimitExceeded {
                limit: "max_file_bytes",
            });
        }
        if self.offset == self.bytes.len() {
            return Ok(None);
        }
        match self.format {
            CaptureFormat::ClassicPcap { .. } => self.next_classic(),
            CaptureFormat::PcapNg => self.next_ng(),
        }
    }

    /// Read up to `n` packets (fewer at EOF), capped by `max_packets`
    /// per batch. Errors abort the batch.
    pub fn read_packets(&mut self, n: usize) -> Result<Vec<Packet>, CaptureError> {
        let cap = n.min(self.limits.max_packets as usize);
        let mut out = Vec::new();
        for _ in 0..cap {
            match self.next_packet()? {
                Some(packet) => out.push(packet),
                None => break,
            }
        }
        Ok(out)
    }

    // ---- classic pcap ----

    fn open_classic(bytes: &'a [u8], limits: CaptureLimits) -> Result<Self, CaptureError> {
        let magic = getn(bytes, 0, 4).ok_or(CaptureError::TruncatedHeader {
            needed: 4,
            available: bytes.len(),
        })?;
        // (little-endian?, nanosecond?)
        let mode = match magic {
            [0xD4, 0xC3, 0xB2, 0xA1] => Some((true, false)),
            [0xA1, 0xB2, 0xC3, 0xD4] => Some((false, false)),
            [0x4D, 0x3C, 0xB2, 0xA1] => Some((true, true)),
            [0xA1, 0xB2, 0x3C, 0x4D] => Some((false, true)),
            _ => None,
        };
        let Some((little, nanosecond)) = mode else {
            return Err(CaptureError::UnsupportedFormat {
                magic: bytes.get(..bytes.len().min(4)).unwrap_or(&[]).to_vec(),
            });
        };
        // Global header is 24 bytes; version/linktype live past the magic.
        if bytes.len() < 24 {
            // Magic consumed 4; the version field needs the next 4.
            return Err(CaptureError::TruncatedHeader {
                needed: 4,
                available: bytes.len().saturating_sub(4),
            });
        }
        let link_raw = u16_at(bytes, 20, little);
        Ok(PcapReader {
            bytes,
            limits,
            format: CaptureFormat::ClassicPcap { nanosecond },
            little,
            link: Some(LinkType::from_value(link_raw)),
            offset: 24,
            returned: 0,
            ng_endian: Endian::Little,
            ng_tick_hz: Vec::new(),
        })
    }

    fn next_classic(&mut self) -> Result<Option<Packet>, CaptureError> {
        let frame = self.returned + 1;
        let rest = self.bytes.len() - self.offset;
        let Some(hdr) = getn(self.bytes, self.offset, 16) else {
            return Err(CaptureError::TruncatedPacket {
                frame,
                needed: 16,
                available: rest,
            });
        };
        let at = self.offset;
        let raw = |off: usize| {
            get4(hdr, off).map(|w| {
                if self.little {
                    u32::from_le_bytes(w)
                } else {
                    u32::from_be_bytes(w)
                }
            })
        };
        let (Some(ts_sec), Some(ts_frac), Some(caplen), Some(origlen)) = (
            raw(0).map(u64::from),
            raw(4).map(u64::from),
            raw(8),
            raw(12),
        ) else {
            // Unreachable: `hdr` is exactly 16 bytes by construction.
            return Err(CaptureError::TruncatedPacket {
                frame,
                needed: 16,
                available: 0,
            });
        };
        if caplen > origlen {
            return Err(CaptureError::InconsistentLengths {
                frame,
                captured_len: caplen,
                original_len: origlen,
            });
        }
        if caplen > self.limits.max_captured_packet_bytes {
            return Err(CaptureError::PacketTooLarge {
                frame,
                captured_len: caplen,
                limit: self.limits.max_captured_packet_bytes,
            });
        }
        let data_at = at + 16;
        let need = caplen as usize;
        let Some(data) = getn(self.bytes, data_at, need) else {
            return Err(CaptureError::TruncatedPacket {
                frame,
                needed: need,
                available: self.bytes.len() - data_at,
            });
        };
        let timestamp = match self.format {
            // Nanoseconds need no scaling; microseconds scale by 1,000.
            // `from_fraction` carries hostile overflow into seconds.
            CaptureFormat::ClassicPcap { nanosecond: true } => {
                Timestamp::from_fraction(ts_sec, ts_frac, 1_000_000_000)
            }
            _ => Timestamp::from_fraction(ts_sec, ts_frac, 1_000_000),
        };
        let packet = Packet {
            index: frame,
            captured_len: caplen,
            original_len: origlen,
            data: data.to_vec(),
            timestamp,
        };
        self.offset = data_at + need;
        self.returned += 1;
        Ok(Some(packet))
    }

    // ---- pcapng ----

    fn open_ng(bytes: &'a [u8], limits: CaptureLimits) -> Result<Self, CaptureError> {
        // First block must be a Section Header with a sane length.
        let Some(head) = getn(bytes, 0, 16) else {
            return Err(CaptureError::TruncatedHeader {
                needed: 16,
                available: bytes.len(),
            });
        };
        let endian = detect_section(head).ok_or(CaptureError::UnsupportedFormat {
            magic: bytes.get(..bytes.len().min(4)).unwrap_or(&[]).to_vec(),
        })?;
        let version_major = endian.u16(get2(head, 12).unwrap_or([0, 0]));
        if version_major != 1 {
            return Err(CaptureError::UnsupportedVersion {
                offset: 0,
                major: version_major,
            });
        }
        let mut reader = PcapReader {
            bytes,
            limits,
            format: CaptureFormat::PcapNg,
            little: true,
            link: None,
            offset: 0,
            returned: 0,
            ng_endian: endian,
            ng_tick_hz: Vec::new(),
        };
        // Consume the SHB, then eagerly consume leading IDBs so link_type()
        // is meaningful immediately after open.
        let shb_len = endian.u32(get4(head, 4).unwrap_or([0, 0, 0, 0])) as usize;
        if shb_len < 28 || !shb_len.is_multiple_of(4) {
            return Err(CaptureError::BlockLengthMismatch { offset: 0 });
        }
        reader.offset = shb_len;
        while let Some(block) = reader.peek_block()? {
            if block.block_type != 1 {
                break;
            }
            reader.consume_interface_block(block)?;
        }
        Ok(reader)
    }

    /// Peek the next block header without consuming it.
    fn peek_block(&self) -> Result<Option<RawBlock>, CaptureError> {
        if self.offset == self.bytes.len() {
            return Ok(None);
        }
        let Some(hdr) = getn(self.bytes, self.offset, 12) else {
            return Err(CaptureError::BlockLengthMismatch {
                offset: self.offset,
            });
        };
        let (Some(type_raw), Some(len_raw)) = (get4(hdr, 0), get4(hdr, 4)) else {
            // Unreachable: `hdr` is exactly 12 bytes (checked by the caller).
            return Err(CaptureError::BlockLengthMismatch {
                offset: self.offset,
            });
        };
        let block_type = self.ng_endian.u32(type_raw);
        let total_len = self.ng_endian.u32(len_raw);
        if total_len < 12 || !total_len.is_multiple_of(4) {
            return Err(CaptureError::BlockLengthMismatch {
                offset: self.offset,
            });
        }
        if total_len > self.limits.max_block_bytes {
            return Err(CaptureError::LimitExceeded {
                limit: "max_block_bytes",
            });
        }
        Ok(Some(RawBlock {
            offset: self.offset,
            block_type,
            total_len: total_len as usize,
        }))
    }

    /// Consume one Interface Description Block, recording link + resolution.
    fn consume_interface_block(&mut self, block: RawBlock) -> Result<(), CaptureError> {
        let body = self.block_body(block)?;
        let Some(link_raw) = get2(body, 0) else {
            return Err(CaptureError::BlockLengthMismatch {
                offset: block.offset,
            });
        };
        if body.len() < 8 {
            return Err(CaptureError::BlockLengthMismatch {
                offset: block.offset,
            });
        }
        if self.ng_tick_hz.len() as u64 >= u64::from(self.limits.max_interfaces) {
            return Err(CaptureError::LimitExceeded {
                limit: "max_interfaces",
            });
        }
        let link = LinkType::from_value(self.ng_endian.u16(link_raw));
        // Options walk for if_tsresol (code 9, 1-byte value).
        let mut per_sec: u64 = 1_000_000;
        let mut at = 8usize;
        while let Some(code_raw) = get2(body, at) {
            let code = self.ng_endian.u16(code_raw);
            let Some(len_raw) = get2(body, at + 2) else {
                break;
            };
            let len = usize::from(self.ng_endian.u16(len_raw));
            let val_at = at + 4;
            let Some(padded) = len.next_multiple_of(4).checked_add(val_at) else {
                break;
            };
            if padded > body.len() {
                break;
            }
            if code == 9 && len == 1 {
                let Some(resol) = body.get(val_at).copied() else {
                    break;
                };
                per_sec = if resol & 0x80 != 0 {
                    1u64 << (resol & 0x7F).min(62)
                } else {
                    10u64.saturating_pow(u32::from(resol).min(18))
                };
            }
            if code == 0 {
                break;
            }
            at = padded;
        }
        if self.link.is_none() {
            self.link = Some(link);
        }
        self.ng_tick_hz.push(per_sec);
        self.offset = block.offset + block.total_len;
        Ok(())
    }

    fn next_ng(&mut self) -> Result<Option<Packet>, CaptureError> {
        loop {
            let Some(block) = self.peek_block()? else {
                return Ok(None);
            };
            match block.block_type {
                0x0A0D0D0A => {
                    // New section: re-detect endianness from its SHB.
                    let Some(head) = getn(self.bytes, block.offset, 16) else {
                        return Err(CaptureError::TruncatedPacket {
                            frame: self.returned + 1,
                            needed: 16,
                            available: self.bytes.len() - block.offset,
                        });
                    };
                    let endian = detect_section(head).ok_or(CaptureError::BlockLengthMismatch {
                        offset: block.offset,
                    })?;
                    self.ng_endian = endian;
                    let version_major = endian.u16(get2(head, 12).unwrap_or([0, 0]));
                    if version_major != 1 {
                        return Err(CaptureError::UnsupportedVersion {
                            offset: block.offset,
                            major: version_major,
                        });
                    }
                    self.offset = block.offset + block.total_len;
                }
                1 => {
                    self.consume_interface_block(block)?;
                }
                6 => {
                    return self.read_epb(block);
                }
                3 => {
                    return self.read_spb(block);
                }
                _ => {
                    // Unknown blocks (statistics, name resolution, future
                    // types) skip by declared length — forward compatible.
                    self.block_body(block)?;
                    self.offset = block.offset + block.total_len;
                }
            }
        }
    }

    /// Validated block body (without leading/trailing length words).
    fn block_body(&self, block: RawBlock) -> Result<&'a [u8], CaptureError> {
        let Some(body) = getn(self.bytes, block.offset, block.total_len) else {
            return Err(CaptureError::TruncatedPacket {
                frame: self.returned + 1,
                needed: block.total_len,
                available: self.bytes.len() - block.offset,
            });
        };
        let Some(trailer_raw) = get4(body, block.total_len - 4) else {
            return Err(CaptureError::BlockLengthMismatch {
                offset: block.offset,
            });
        };
        let trailer = self.ng_endian.u32(trailer_raw);
        if trailer != block.total_len as u32 {
            return Err(CaptureError::BlockLengthMismatch {
                offset: block.offset,
            });
        }
        // 8 leading + 4 trailing length words excluded.
        getn(body, 8, block.total_len - 12).ok_or(CaptureError::BlockLengthMismatch {
            offset: block.offset,
        })
    }

    fn read_epb(&mut self, block: RawBlock) -> Result<Option<Packet>, CaptureError> {
        let frame = self.returned + 1;
        let body = self.block_body(block)?;
        if body.len() < 20 {
            return Err(CaptureError::BlockLengthMismatch {
                offset: block.offset,
            });
        }
        let get = |at: usize| get4(body, at).map(|w| self.ng_endian.u32(w)).unwrap_or(0);
        let (Some(hi), Some(lo)) = (get4(body, 4), get4(body, 8)) else {
            // Unreachable: `body` holds at least 20 bytes (checked above).
            return Err(CaptureError::BlockLengthMismatch {
                offset: block.offset,
            });
        };
        let iface = get(0) as usize;
        let ticks = self.ng_endian.u64_words(hi, lo);
        let caplen = get(12);
        let origlen = get(16);
        // `get4(...).unwrap_or(zero)` above cannot mislead: short bodies
        // already returned `BlockLengthMismatch`, so these reads are exact.
        self.read_packet_data(block, frame, caplen, origlen, 20, Some((ticks, iface)))
    }

    fn read_spb(&mut self, block: RawBlock) -> Result<Option<Packet>, CaptureError> {
        let frame = self.returned + 1;
        let body = self.block_body(block)?;
        if body.len() < 4 {
            return Err(CaptureError::BlockLengthMismatch {
                offset: block.offset,
            });
        }
        let origlen = self.ng_endian.u32(get4(body, 0).unwrap_or([0, 0, 0, 0]));
        let caplen = (block.total_len as u32).saturating_sub(16);
        self.read_packet_data(block, frame, caplen, origlen, 4, None)
    }

    fn read_packet_data(
        &mut self,
        block: RawBlock,
        frame: u64,
        caplen: u32,
        origlen: u32,
        data_off: usize,
        ts: Option<(u64, usize)>,
    ) -> Result<Option<Packet>, CaptureError> {
        if caplen > origlen {
            return Err(CaptureError::InconsistentLengths {
                frame,
                captured_len: caplen,
                original_len: origlen,
            });
        }
        if caplen > self.limits.max_captured_packet_bytes {
            return Err(CaptureError::PacketTooLarge {
                frame,
                captured_len: caplen,
                limit: self.limits.max_captured_packet_bytes,
            });
        }
        let body = self.block_body(block)?;
        let need = caplen as usize;
        let padded = need.next_multiple_of(4);
        let Some(end) = data_off.checked_add(padded) else {
            return Err(CaptureError::BlockLengthMismatch {
                offset: block.offset,
            });
        };
        if end > body.len() {
            return Err(CaptureError::TruncatedPacket {
                frame,
                needed: data_off + need,
                available: body.len(),
            });
        }
        let Some(data) = getn(body, data_off, need) else {
            return Err(CaptureError::TruncatedPacket {
                frame,
                needed: data_off + need,
                available: body.len(),
            });
        };
        let timestamp = match ts {
            Some((ticks, iface)) => {
                let per_sec = self.ng_tick_hz.get(iface).copied().unwrap_or(1_000_000);
                Timestamp::from_fraction(0, ticks, per_sec)
            }
            None => Timestamp {
                seconds: 0,
                nanos: 0,
            },
        };
        let packet = Packet {
            index: frame,
            captured_len: caplen,
            original_len: origlen,
            data: data.to_vec(),
            timestamp,
        };
        self.offset = block.offset + block.total_len;
        self.returned += 1;
        Ok(Some(packet))
    }
}

/// Framed block header (type + total length + file offset).
#[derive(Debug, Clone, Copy)]
struct RawBlock {
    offset: usize,
    block_type: u32,
    total_len: usize,
}

/// `true` when the first four bytes are a pcapng section header.
fn is_pcapng_magic(bytes: &[u8]) -> bool {
    matches!(getn(bytes, 0, 4), Some([0x0A, 0x0D, 0x0D, 0x0A]))
}

/// Detect section endianness from a 16-byte SHB head via the byte-order
/// magic at +8 (version major follows at +12).
fn detect_section(head: &[u8]) -> Option<Endian> {
    let le = |i: usize| get4(head, i).map(u32::from_le_bytes);
    let be = |i: usize| get4(head, i).map(u32::from_be_bytes);
    if le(0) != Some(0x0A0D0D0A) && be(0) != Some(0x0A0D0D0A) {
        return None;
    }
    if le(8) == Some(0x1A2B3C4D) {
        Some(Endian::Little)
    } else if be(8) == Some(0x1A2B3C4D) {
        Some(Endian::Big)
    } else {
        None
    }
}

/// Read `u16` at an offset with an explicit endianness (bounds-checked).
fn u16_at(bytes: &[u8], at: usize, little: bool) -> u16 {
    get2(bytes, at).map_or(0, |w| {
        if little {
            u16::from_le_bytes(w)
        } else {
            u16::from_be_bytes(w)
        }
    })
}
