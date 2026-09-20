#!/bin/sh
# kiwi-sandbox guest agent — emits kiwi.sandbox.report/1 JSON to
# <out_dir>/report.json, then exits. Busybox applets only (the base image
# is a busybox rootfs); every optional tool is probed and its absence
# recorded in agent_notes rather than silently degrading.
#
# Usage: kiwi-agent.sh <artifact> <out_dir> <timeout_secs> <max_mem_mb>
#
# Evidence captured:
#   - process tree: polled `ps` snapshots while the payload runs (honest
#     limit: sub-poll-interval processes can evade — noted in contract)
#   - fs diff: created/modified/deleted across the whole guest FS,
#     flagged whether writes landed outside the /kiwi-work sandbox dir
#   - network: egress is enforced structurally (payload runs under
#     `unshare -rn`); the agent proves it with an in-netns deny probe and
#     reports the outside-netns reachability as context. There is no
#     per-packet logging on this tier — attempts_observed stays empty.
#   - resource limits: probed ulimits, applied to the payload subshell
#
# Fail-closed rule: if `unshare` is missing the payload is NEVER executed
# (egress would be uncontrolled — contract invariant 6).

ART="$1"; OUT="$2"; TMO="${3:-60}"; MEM_MB="${4:-256}"
WORK=/kiwi-work
[ -n "$ART" ] && [ -n "$OUT" ] || exit 2
mkdir -p "$OUT" "$WORK" 2>/dev/null
NOTES_FILE="$OUT/notes.txt"; : > "$NOTES_FILE"
note() { echo "$1" >> "$NOTES_FILE"; }

VMEM_KB=$(( MEM_MB * 1024 ))

# ---- capability probes -------------------------------------------------
if ps -o pid,ppid,comm,args >/dev/null 2>&1; then
    PSCMD='ps -o pid,ppid,comm,args'; PSFMT=long
else
    PSCMD='ps'; PSFMT=short
    note 'ps -o unsupported: ppid unavailable in process evidence'
fi
HAVE_UNSHARE=0; command -v unshare >/dev/null 2>&1 && HAVE_UNSHARE=1
[ "$HAVE_UNSHARE" = 1 ] || note 'unshare missing: payload NOT executed (fail-closed, egress uncontrolled)'

# ---- resource limits: probe each, record what the kernel accepts -------
: > "$OUT/limits.txt"
probe_lim() { # flag value key
    if ( ulimit "-$1" "$2" ) 2>/dev/null; then
        echo "\"$3\": $2" >> "$OUT/limits.txt"
    else
        note "ulimit -$1 unsupported"
    fi
}
probe_lim t "$TMO" cpu_secs
probe_lim f 131072 file_blocks        # 64 MiB max file (512B blocks)
probe_lim n 64 nofile
probe_lim v "$VMEM_KB" vmem_kb
probe_lim p 256 nproc

# ---- egress evidence ----------------------------------------------------
# In-netns deny probe: must be unreachable — that is the enforcement proof.
if [ "$HAVE_UNSHARE" = 1 ]; then
    PROBE_IN=$(unshare -rn sh -c 'nc -w2 1.1.1.1 443 </dev/null >/dev/null 2>&1 && echo reachable || echo unreachable' 2>/dev/null)
    [ -n "$PROBE_IN" ] || PROBE_IN=untested
    DNS_IN=$(unshare -rn sh -c 'nslookup kiwi-sandbox-test.invalid >/dev/null 2>&1 && echo resolved || echo blocked' 2>/dev/null)
    [ -n "$DNS_IN" ] || DNS_IN=untested
else
    PROBE_IN=untested; DNS_IN=untested
fi
# Context only: can the agent's own (unrestricted) namespace reach out?
PROBE_OUT=$(nc -w2 1.1.1.1 443 </dev/null >/dev/null 2>&1 && echo reachable || echo blocked)

# ---- FS baseline --------------------------------------------------------
find / -xdev -type f 2>/dev/null | sort > "$OUT/fs-before.txt"
touch "$OUT/.t0"

# ---- payload run --------------------------------------------------------
EXIT=null; TIMED_OUT=false; PERR=null
if [ "$HAVE_UNSHARE" = 1 ]; then
    : > "$OUT/stdout.log"; : > "$OUT/stderr.log"; : > "$OUT/procs.txt"
    (
        ulimit -t "$TMO" -f 131072 -n 64 -v "$VMEM_KB" 2>/dev/null
        cd "$WORK" 2>/dev/null
        exec unshare -rn timeout "$TMO" sh "$ART"
    ) > "$OUT/stdout.log" 2> "$OUT/stderr.log" &
    PAYPID=$!
    # immediate snapshot + poll loop (bounded at 4096 lines)
    eval "$PSCMD" >> "$OUT/procs.txt" 2>/dev/null
    (
        while kill -0 "$PAYPID" 2>/dev/null; do
            eval "$PSCMD" >> "$OUT/procs.txt" 2>/dev/null
            [ "$(wc -l < "$OUT/procs.txt" 2>/dev/null || echo 0)" -ge 4096 ] && break
            sleep 0.2
        done
    ) &
    POLLER=$!
    wait "$PAYPID"; EXIT=$?
    kill "$POLLER" 2>/dev/null; wait "$POLLER" 2>/dev/null
    [ "$EXIT" = 124 ] || [ "$EXIT" = 137 ] && TIMED_OUT=true
else
    PERR='"egress isolation unavailable (unshare missing); payload refused"'
fi

# ---- FS diff ------------------------------------------------------------
find / -xdev -type f 2>/dev/null | sort > "$OUT/fs-after.txt"
grep -Fxv -f "$OUT/fs-before.txt" "$OUT/fs-after.txt" > "$OUT/fs-created.txt" 2>/dev/null || true
grep -Fxv -f "$OUT/fs-after.txt" "$OUT/fs-before.txt" > "$OUT/fs-deleted.txt" 2>/dev/null || true
find / -xdev -type f -newer "$OUT/.t0" 2>/dev/null | sort > "$OUT/fs-newer.txt"
grep -Fxf "$OUT/fs-before.txt" "$OUT/fs-newer.txt" 2>/dev/null | grep -Fxf "$OUT/fs-after.txt" > "$OUT/fs-modified.txt" 2>/dev/null || true
# strip harness paths: /kiwi-out/* /kiwi-agent.sh /kiwi-artifact (keep /kiwi-work — that IS the payload's workspace)
for f in created modified deleted; do
    grep -v -e "^$OUT/" -e '^/kiwi-agent\.sh$' -e '^/kiwi-artifact$' "$OUT/fs-$f.txt" > "$OUT/fs-$f.f" 2>/dev/null || true
    mv "$OUT/fs-$f.f" "$OUT/fs-$f.txt" 2>/dev/null || true
done
# sha256 of created files (first 256)
if command -v sha256sum >/dev/null 2>&1; then
    head -n 256 "$OUT/fs-created.txt" | xargs sha256sum > "$OUT/fs-sha.txt" 2>/dev/null || true
else
    : > "$OUT/fs-sha.txt"; note 'sha256sum unavailable: created-file hashes omitted'
fi

# ---- emit report.json ---------------------------------------------------
# tail -c → JSON-escaped single line (newlines become \n escapes)
tail_esc() {
    tail -c 65536 "$1" 2>/dev/null | awk '
        { gsub(/\r/, ""); gsub(/\\/, "\\\\"); gsub(/"/, "\\\"")
          printf "%s%s", (NR > 1 ? "\\n" : ""), $0 }'
}

emit_fs() { # $1=kind $2=listfile → JSON objects on stdout
    awk -v k="$1" -v wd="$WORK/" -v hf="$OUT/fs-sha.txt" '
        BEGIN {
            # sha256sum lines: 64 hex chars, two spaces, then the path
            while ((getline l < hf) > 0) { H[substr(l, 67)] = substr(l, 1, 64) }
            f = 1
        }
        {
            gsub(/\\/, "\\\\"); gsub(/"/, "\\\"")
            ow = (index($0, wd) == 1) ? "false" : "true"
            sha = ($0 in H) ? "\"" H[$0] "\"" : "null"
            printf "%s{\"path\":\"%s\",\"kind\":\"%s\",\"outside_workdir\":%s,\"sha256\":%s}", f ? "" : ",", $0, k, ow, sha
            f = 0
        }' "$2"
}

emit_procs() {
    sort -u "$OUT/procs.txt" 2>/dev/null | awk -v fmt="$PSFMT" '
        BEGIN { f = 1 }
        { pid = ""; ppid = "0"; exe = "" }
        NR == 1 && /PID/ { next }     # header line
        fmt == "long" && NF >= 3 {
            pid = $1; ppid = $2; exe = $3; $1 = ""; $2 = ""; $3 = ""
        }
        fmt == "short" && NF >= 4 {
            pid = $1; ppid = "0"; exe = $4; $1 = ""; $2 = ""; $3 = ""; $4 = ""
        }
        pid ~ /^[0-9]+$/ {
            gsub(/^ +/, ""); gsub(/\\/, "\\\\"); gsub(/"/, "\\\"")
            gsub(/\\/, "\\\\", exe); gsub(/"/, "\\\"", exe)
            printf "%s{\"pid\":%s,\"ppid\":%s,\"exe\":\"%s\",\"args\":\"%s\"}", f ? "" : ",", pid, ppid, exe, $0
            f = 0
        }'
}

emit_notes() {
    awk 'BEGIN { f = 1 } { gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); printf "%s\"%s\"", f ? "" : ",", $0; f = 0 }' "$NOTES_FILE"
}

LIMITS=$(tr '\n' ',' < "$OUT/limits.txt" | sed 's/,$//')
STAIL=$(tail_esc "$OUT/stdout.log")
ETAIL=$(tail_esc "$OUT/stderr.log")
OUTSIDE=$( { grep -v "^$WORK/" "$OUT/fs-created.txt" "$OUT/fs-modified.txt" 2>/dev/null || true; } | grep -cv '^$' )
OUTSIDE=${OUTSIDE:-0}

{
    printf '{\n  "schema": "kiwi.sandbox.report/1",\n'
    printf '  "agent": "shell-busybox",\n'
    printf '  "exit_code": %s,\n' "$EXIT"
    printf '  "timed_out": %s,\n' "$TIMED_OUT"
    printf '  "payload_error": %s,\n' "$PERR"
    printf '  "limits_applied": {%s},\n' "$LIMITS"
    printf '  "writes_outside_workdir": %s,\n' "$OUTSIDE"
    printf '  "processes": ['; emit_procs; printf '],\n'
    printf '  "fs_changes": ['
    emit_fs created "$OUT/fs-created.txt"
    c=$(wc -l < "$OUT/fs-created.txt" 2>/dev/null || echo 0); m=$(wc -l < "$OUT/fs-modified.txt" 2>/dev/null || echo 0)
    [ "$c" -gt 0 ] && [ "$m" -gt 0 ] && printf ','
    emit_fs modified "$OUT/fs-modified.txt"
    d=$(wc -l < "$OUT/fs-deleted.txt" 2>/dev/null || echo 0)
    { [ "$c" -gt 0 ] || [ "$m" -gt 0 ]; } && [ "$d" -gt 0 ] && printf ','
    emit_fs deleted "$OUT/fs-deleted.txt"
    printf '],\n'
    printf '  "network": {\n'
    printf '    "enforced": "%s",\n' "$( [ "$HAVE_UNSHARE" = 1 ] && echo netns-drop || echo none )"
    printf '    "probe_inside_netns": "%s",\n' "$PROBE_IN"
    printf '    "probe_outside_netns": "%s",\n' "$PROBE_OUT"
    printf '    "dns": "%s",\n' "$DNS_IN"
    printf '    "attempts_observed": []\n  },\n'
    printf '  "stdout_tail": "%s",\n' "$STAIL"
    printf '  "stderr_tail": "%s",\n' "$ETAIL"
    printf '  "agent_notes": ['; emit_notes; printf ']\n'
    printf '}\n'
} > "$OUT/report.json"

exit 0
