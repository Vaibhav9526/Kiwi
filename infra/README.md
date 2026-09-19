# KIWI local infrastructure (T-131 · ADR-007)

Reproducible local services for development and testing. **The Tauri desktop
app never runs here** — Docker is for services (PostgreSQL, mailpit,
kiwi-admin), not the client.

## Services

| service | image | host ports | purpose |
|---------|-------|------------|---------|
| `db` | postgres:17-alpine (+ `pgdata` named volume) | `${POSTGRES_PORT:-5432}` | org/service data for kiwi-admin (ADR-006) |
| `mailpit` | axllent/mailpit:v1.31.2 | SMTP 1025 · POP3 1100 · UI/API 8025 | dev/test mail server: SMTP+POP3 (T-114 interop profile) |
| `greenmail` | greenmail/standalone:2.1.14 (IMAP-only surface) | IMAP `${GREENMAIL_IMAP_PORT:-1143}` | live IMAP for sync tests (T-147 — mailpit serves no IMAP, verified) |
| `admin` | built from `kiwi-admin/Dockerfile` | `${KIWI_ADMIN_PORT:-3001}` | kiwi-admin service (entrypoint lands with T-130) |

## Start / stop

```powershell
cp .env.example .env        # once (PowerShell: Copy-Item .env.example .env)
docker compose up -d        # start db + mailpit + greenmail (+ admin image build)
docker compose ps           # health states (greenmail has no in-image healthcheck — see below)
docker compose logs -f      # follow logs (or: docker compose logs -f admin)
docker compose stop         # stop, keep volumes
docker compose down         # stop + remove containers (keeps pgdata volume)
docker compose down -v      # stop + DELETE the pgdata volume (data loss!)
```

Run the verification suite (T-133):

```powershell
python -m unittest discover -s tests/infra -v
```

## What's working vs pending

- `db` and `mailpit` are fully operational once the daemon is up:
  `pg_isready` healthcheck on `db`; mailpit UI at
  `http://localhost:8025`, SMTP on 1025 (send a test mail → appears in UI).
- `greenmail` serves live IMAP on 1143 (greeting + CAPABILITY asserted by
  T-133). It has no in-image healthcheck (Zulu base ships no nc/wget/curl —
  verified) — external assertions are the health signal. JVM boot takes
  ~30s; be patient after `up`.
- `admin` is **expected-red until T-130**: the image builds green (type
  gate inside the Dockerfile) but there is no `src/server.ts` entrypoint
  or `GET /healthz` yet, so the container exits and its healthcheck fails.
  T-130 delivers: `src/server.ts`, `/healthz` (+ `/readyz` on DATABASE_URL),
  Drizzle migrations wiring. Then `docker compose up admin` goes green
  with no compose changes.
- Sandbox (T-132, ADR-008) is **not** in this compose file on purpose:
  disposable-VM isolation is a different boundary from service containers.
  Docker is infra, never the hostile-code boundary.

## Mailpit quick check (kiwi-mail interop)

```powershell
# SMTP delivery lands in the UI/API:
python -c "import smtplib; s=smtplib.SMTP('localhost',1025); s.sendmail('a@kiwi-test.invalid',['b@kiwi-test.invalid'],'Subject: hi\r\n\r\nbody'); s.quit()"
curl http://localhost:8025/api/v1/messages
```

## Troubleshooting

| symptom | fix |
|---------|-----|
| `docker info` fails / pipe missing | start Docker Desktop, wait for green, retry |
| port already in use (5432/1025/1143/8025/3001) | local Postgres/mail server running? stop it or override ports in `.env` |
| `db` unhealthy, auth errors | `docker compose down -v` ONLY if dev data is disposable (resets password + volume together) |
| `admin` exits / unhealthy | expected until T-130 (see above); check `docker compose logs admin` |
| `.env` missing | compose requires it (`env_file ... required: true`); copy from `.env.example` |

## ADR-009 justification (why this shape)

- **Why compose (not bare containers):** one command, health-gated startup
  order (`admin` waits for healthy `db`), named volume, versioned file.
- **Why these images:** official `postgres:17-alpine` (small, pg_isready
  in-image); `axllent/mailpit:v1.31.2` pinned (maintained, SMTP+IMAP+POP3+API
  in one 13 MB image — exactly the T-114 interop need; GreenMail needs a
  JVM, MailHog is unmaintained).
- **Why GreenMail for IMAP (T-147, not Dovecot):** mailpit provably serves
  no IMAP (TCP accept, zero bytes — probed). Dovecot would need baked
  Maildir + user config (custom image, ongoing maintenance). GreenMail
  standalone is purpose-built for fixture mail (all protocols, zero-config
  test users, IMAP-only surface enabled here), one maintained image
  (~109 MB). Auth-disabled defaults are fine — synthetic mail only,
  localhost-bound, never real data.
- **Why no Redis/Kafka/etc.:** no concrete need (ADR-007) — adding later
  follows ADR-009.
- **Security:** dev-only default password, `.env` gitignored (pair with
  `.env.example`); containers share no host mounts except the PG data
  volume; no mailbox/credential mounts anywhere. Containers are NOT the
  hostile-code boundary (ADR-008).
- **Cost:** ~3 containers, <500 MB images, idle CPU ~0.
