# Home server deployment

Two ways to run the backend, both built from the same image (`crates/yap-server/Dockerfile`):

1. **`compose.yml`** in this folder: Caddy (TLS) + gateway + Postgres, for a server that is
   reachable directly or through a TCP-passthrough VPS (see `../vps`).
2. **Add the services to an existing Docker Compose stack** that already has its own tunnel and
   proxy. You need three services: Postgres, the gateway, and (if you tunnel through a VPS with
   [frp](https://github.com/fatedier/frp)) an `frpc` that maps the gateway's port 8080 to a
   remote port on the VPS. Nothing needs to be published on a host port.

## Gateway settings

All settings are environment variables (see `.env.example`). The ones that matter:

| Variable | Notes |
|---|---|
| `YAP_DOMAIN` | The public hostname. It must equal the host people browse to: OPAQUE binds it into every login. |
| `YAP_SERVER_SECRET` | 32+ random bytes, base64. **Back it up separately from the database**: without it nobody can log in. |
| `YAP_WEB_DIR` | Serve the built web app (`just web-app`) from the gateway. |
| `SMTP_*` | A real SMTP relay for signup and reset codes. A relay that only accepts hardware alerts or a fixed recipient will not work. |

## What the reverse proxy in front of the gateway must do

The gateway speaks plain HTTP (and WebSocket on `/ws`) and expects something in front of it to
provide TLS. That proxy must:

- **Set `X-Forwarded-For` to the real client address.** The gateway uses it only for in-memory
  rate limits. If the header is missing, every visitor shares one rate-limit bucket (so a few
  signups lock everyone out); if the proxy passes through a client-supplied value, limits can be
  evaded.
- **Pass WebSocket upgrades** on `/ws` and allow long-lived connections (live typing and
  delivery run over it).
- **Not log requests.** The server keeps no metadata logs; a proxy that does defeats that.
- Send HSTS (the gateway sets the other security headers itself).
