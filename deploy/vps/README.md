# VPS edge setup

The VPS forwards `yap.leafyserver.tech:443` to the home server through a WireGuard tunnel.
It terminates no TLS and keeps no logs.

1. **DNS (Cloudflare):** `yap.leafyserver.tech` A record -> VPS public IP, with the proxy
   **off** ("DNS only", grey cloud). Orange cloud would let Cloudflare see your traffic.
2. **WireGuard:** VPS = `10.77.0.1`, home server = `10.77.0.2`. Generate keys with `wg genkey`;
   never commit them. Example `/etc/wireguard/wg0.conf` on the VPS:

   ```ini
   [Interface]
   Address = 10.77.0.1/24
   ListenPort = 51820
   PrivateKey = <vps-private-key>

   [Peer]            # home server
   PublicKey = <home-public-key>
   AllowedIPs = 10.77.0.2/32
   ```

   On the home server, point the peer at the VPS endpoint and set `PersistentKeepalive = 25`
   so the tunnel survives NAT.
3. **HAProxy:** install it and use `haproxy.cfg` from this directory. Open only 443/tcp and
   51820/udp on the VPS firewall.
4. **Scaling:** add each new machine to the WireGuard network and add a `server` line in
   `haproxy.cfg`.
