# Router DNS for VPN destinations

On this OpenWrt setup, Hysteria uses the system resolver. The router and LAN clients can continue to use dnsmasq, including its local names and DHCP settings. For public names, dnsmasq forwards to Stubby on loopback. Stubby authenticates Cloudflare (`1.1.1.1`) first and uses Google (`8.8.8.8`) as the fallback. Using TLS matters on networks where an ordinary port-53 reply can come from an intermediary.

Merge these settings into the **existing** `/etc/config/dhcp` dnsmasq section; preserve DHCP ranges and local zones. The general upstream should be just `127.0.0.1#5453`. `noresolv` prevents fallback to WAN-provided DNS; `localuse` keeps the router's own resolver on loopback.

```text
option noresolv '1'
option localuse '1'
list server '127.0.0.1#5453'
```

Relevant settings in `/etc/config/stubby` (UCI mode). Keep the existing WAN trigger and package defaults for unrelated options. The two resolver sections below replace the upstream list; order matters.

```text
config stubby 'global'
    option enabled '1'
    option manual '0'
    option trigger 'wan'
    list listen_address '127.0.0.1@5453'
    list listen_address '0::1@5453'
    list dns_transport 'GETDNS_TRANSPORT_TLS'
    option tls_authentication '1'
    option round_robin_upstreams '0'
    option tls_connection_retries '1'
    option tls_backoff_time '30'
    option timeout '5000'

config resolver
    option address '1.1.1.1'
    option tls_auth_name 'cloudflare-dns.com'

config resolver
    option address '8.8.8.8'
    option tls_auth_name 'dns.google'
```

Back up DNS settings before changing them, including the vendor's `stubby-vpn` configuration if present. Start Stubby and verify it can resolve through the TLS listener **before** switching dnsmasq. Reload/restart dnsmasq, preserving the WAN interface and Hysteria process. If validation fails, restore the previous files and service states.

To verify the full path, use a native Hysteria client with a loopback SOCKS listener and `curl --socks5-hostname` to send destination names through the tunnel. Check for the test names at the loopback DNS forwarder and an established TLS connection from Stubby to port 853 of the expected upstream. Test failover in an isolated Stubby instance: making the primary's certificate name invalid must allow an answer over authenticated TLS from the secondary. Do not disable certificate checks or interrupt production clients for this test.
