# Caddy with the Cloudflare DNS plugin, so certificates use DNS-01 (no inbound port 80 needed).
FROM caddy:2-builder AS build
RUN xcaddy build --with github.com/caddy-dns/cloudflare

FROM caddy:2
COPY --from=build /usr/bin/caddy /usr/bin/caddy
