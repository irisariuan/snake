# snake

Split tunnelling for **Asuswrt-Merlin** routers, written in Go, with a web UI
in the router's *Addons* menu.

Pick what goes through which VPN client by domain rule (plain domains,
wildcards, regexes, keywords, exclusions, CNAME chains), ASN, CIDR or device. Each
policy has failover between tunnels, a per-policy kill switch, and leak
protection that covers DNS, DoH/DoT, IPv6 and WebRTC. The main use case is
streaming services (Netflix, Disney+, ...) that must exit in a specific country
while everything else stays on your normal connection.

Inspired by and able to import from Ranger802004's
[Domain VPN Routing](https://github.com/Ranger802004/asusmerlin/tree/main/domain_vpn_routing).

## What it does differently from Domain VPN Routing

| | Domain VPN Routing | snake |
|---|---|---|
| Domain → IP | `nslookup` polling on cron / AdGuardHome log | **in real time**: every DNS answer is matched before the client receives it |
| Domain rules | domain list | suffix, exact, subdomains-only, `*`/`**`/`?` wildcards, `~keyword`, `/regex/`, `!exclusions`, `drop:` blocking, CNAME-chain matching |
| Tunnels per policy | one | **ordered list with failover / fail-back** |
| Health | – | interface + WireGuard handshake / OpenVPN state, TCP probes *through* the tunnel, **exit-country check** |
| Tunnel down | traffic goes via WAN | **kill switch** (per policy) or WAN, your choice |
| Device scoping | – | whole device, or device + destinations, groups of devices |
| DNS leaks | – | policy domains resolved **through the tunnel**, port-53 hijack, DoH/DoT/QUIC blocking, DoH canaries, or **routing HTTPS by TLS server name** so DoH/DoT can stay on |
| IPv6 | separate ipsets | routed via tunnel if it has IPv6, otherwise **blocked** for policy traffic |
| WebRTC | – | **session-affinity tracking** (see below) |
| Rule files | – | `.rules` files: import (file/URL, AdGuard/hosts/dnsmasq converted), export, reusable **rule lists**, built-in highlighting editor |
| UI | SSH menu | Merlin Addons page + CLI |

## Requirements

* Asuswrt-Merlin 386.x or newer (Addons API, `ipset`, `dnsmasq` with ipset support)
* One or more VPN clients configured in *VPN → VPN Client* (WireGuard `wgc1-5`
  and/or OpenVPN `ovpnc1-5`; mixing types in one failover list is fine), and/or
  saved WireGuard and OpenVPN configurations that snake runs itself
  ([below](#more-than-ten-vpns-saved-tunnels))
* JFFS custom scripts (the installer turns them on)

In each VPN client you want snake to use, set **"Redirect Internet traffic
through tunnel" to "VPN Director"** and add *no* VPN Director rules. The tunnel
stays up but carries nothing until snake routes traffic into it.

## Install

Download `snake-arm64` (64-bit HND models) or `snake-armv7` (32-bit) from the
[latest release](https://github.com/irisariuan/snake/releases/latest), or
build it yourself:

```sh
make arm64          # 64-bit HND models (RT-AX86U/AX88U/GT-AX6000/BE series)
make armv7          # 32-bit userspace models
scp dist/snake-arm64 admin@router:/tmp/snake
ssh admin@router '/tmp/snake install'
```

`install` copies the binary to `/jffs/addons/snake/snake`, adds hook lines to
`/jffs/scripts/*`, installs the web page and a cron watchdog, then starts the
daemon. Open the router WebUI → **Addons → snake**. If no other addon has
created an Addons menu, the page is under **Tools → snake**.

### Updates and rollback

**Settings → Updates** in the web UI shows the running version and the latest
[GitHub release](https://github.com/irisariuan/snake/releases), with
**Install**, **Roll back** and **Install another version…** buttons. Over
SSH: `snake update [--check]`, `snake update --list`,
`snake update --version <version>` and `snake rollback`.

* The daemon checks for a new release a few minutes after it starts and then
  twice a day. Turn on **Install updates automatically** to install new
  releases without asking.
* An update downloads the binary for this router's CPU, verifies it against
  the release's `SHA256SUMS`, and checks that it runs before replacing
  anything. The old binary is kept as `/jffs/addons/snake/snake.prev`.
* After an update or rollback the daemon restarts. If the new version does not
  start and answer within a minute, snake rolls back by itself and logs it to
  syslog.
* **Roll back** swaps the current and previous binaries, so rolling back twice
  returns you to where you started. Your configuration is not changed.
* **Install another version…** lists every published release (newest
  first, with the running version and the rollback copy marked) and installs
  the one you pick, older or newer: for going back further than the one
  version **Roll back** keeps. It is verified and checked like an update, the
  running version becomes the rollback copy, and if the chosen version does
  not start snake rolls back by itself. Over SSH: `snake update --list` and
  `snake update --version v1.2.3`.
* An older version ignores settings it does not know, and refuses a
  configuration that uses features it lacks (it then fails to start and
  snake rolls back). Going back to an older version, with either button,
  turns **Install updates automatically** off; otherwise the next check
  would install the latest release again.
* Development builds (not a release tag) are never auto-updated. You can still
  install the latest release by hand.
* To use releases from a fork, change **Release repository**.

Uninstall with `snake uninstall`. This removes rules, routes, sets, hooks and
the page; add `--purge` to delete the config too.

## More than ten VPNs: saved tunnels

The firmware has five WireGuard and five OpenVPN clients. For more, save the
files VPN providers hand out for their WireGuard or OpenVPN apps in snake: up
to 20 WireGuard tunnels (`wgx1`–`wgx20`) and 20 OpenVPN clients
(`ovx1`–`ovx20`), which snake runs itself.

**A saved tunnel runs only while an enabled policy uses it**, as its main
tunnel or as a failover backup (backups are kept connected so failover is
instant and their health is known). Saved tunnels no enabled policy lists
stay stopped. snake never starts or stops the firmware's own clients.

1. Web UI → **Tunnels** → **+ Add WireGuard tunnel** or **+ Add OpenVPN
   tunnel**.
2. Paste the file (or **Load .conf/.ovpn file…**), give it a name, and
   **Save & apply**.
3. Add it to a policy's tunnels. It can be mixed with `wgc`/`ovpnc` clients
   in a failover list. On **Save & apply** snake starts it; it is used once
   its health check passes, a few seconds later.

Either way, snake routes traffic itself: the tunnel gets no routes of its
own, and like a firmware client in VPN Director mode it carries only what
snake's policies send into it. DNS settings in the files are ignored (each
policy chooses its resolver) and their scripts are never run.

### WireGuard

```ini
[Interface]
PrivateKey = <your private key>
Address = 10.64.1.2/32, fc00:bbbb::2/128
DNS = 10.64.0.1              # ignored: each policy chooses its resolver

[Peer]
PublicKey = <server public key>
Endpoint = jp-tyo.example.net:51820
AllowedIPs = 0.0.0.0/0, ::/0 # keep: it limits what the tunnel accepts
PersistentKeepalive = 25
```

* `PrivateKey`, `Address`, and a `[Peer]` with `PublicKey`, `Endpoint` and
  `AllowedIPs` are required; `ListenPort`, `MTU` (default 1420),
  `PresharedKey` and `PersistentKeepalive` are optional. Keepalive defaults
  to 25 seconds: a tunnel only counts as healthy after a recent handshake,
  and without keepalives an idle tunnel never handshakes.
* wg-quick's `Table`, `FwMark`, `SaveConfig` and
  `PreUp`/`PostUp`/`PreDown`/`PostDown` are accepted and ignored.
* snake creates the interface with `ip` and configures it with `wg`.
  Changing a tunnel's peers reconfigures it with `wg syncconf`, which keeps
  the session when it can.

### OpenVPN

* A client configuration (`client`, one or more `remote` lines) for a
  routed (`dev tun`) server. Certificates and keys must be inline
  (`<ca>…</ca>`, `<cert>`, `<key>`, `<tls-auth>`, `<tls-crypt>`), as in the
  files most providers hand out: the router has no copy of separate files.
* If the file has `auth-user-pass`, enter the username and password in the
  fields next to it.
* snake runs the router's `openvpn` with the provider's options plus its
  own, which win: the interface (`dev ovxN`), `route-nopull` (pushed routes,
  redirect-gateway and DNS are ignored), `script-security 1` (no scripts) and
  `persist-tun`. Directives for routes, DNS, scripts, logging, management and
  privileges are removed from the file. The client logs to the system log
  as `snake-ovxN`.
* Generated files, including the credentials, live in `/tmp/snake-openvpn`
  (mode 0600; nothing is written to flash) and are removed when the client
  stops. A client that exits (wrong password, server unreachable) is started
  again at most every 30 seconds; changing its file or credentials
  restarts it at once.

### Notes

* Saved tunnels are kept in `config.json` (mode 0600); private keys and
  passwords are shown in the web UI, which needs the API token.
* Disabling a saved tunnel, or deleting it, stops it on **Save & apply**.
  *Emergency disable* leaves running tunnels up but sends no traffic into
  them. Running tunnels stay up across snake restarts and updates.
  `snake uninstall` stops them all.
* Needs the firmware's WireGuard support (kernel module and `wg`) for
  WireGuard and its `openvpn` for OpenVPN; both are on any model that offers
  those VPN clients. Also needs the default 8-bit `mark_mask`.

## Policies

A policy is:

* **Tunnels**, in priority order. The first healthy one is used. Later ones are
  failover backups.
* **Match**: [rules](#domain-rules) (domain rules, `asn:`, `cidr:`), [rule lists](#rule-files-and-rule-lists)
  it includes, and/or devices (MACs, IP addresses or subnets, or groups of them;
  see [VPN server clients](#vpn-server-clients)).
  * destinations only → those destinations, for every device
  * devices only → the **whole device** (most reliable for TV apps)
  * both → those destinations, only for those devices
* **Excluded devices** (optional): devices or groups the policy never
  handles, also when they belong to an included group or subnet. With
  destinations only, this means "every device except these". An excluded
  device is not routed into the policy's tunnel (nor by its WebRTC tracking
  or SNI proxy), not blocked by its `drop:` rules, and not under its leak
  protection; other policies still apply to it. DNS for policy domains is
  resolved the same way for every device, because the router's DNS does
  not know which device will connect.
* **Kill switch**: if no tunnel is usable, block instead of falling back to WAN.
* **Expected exit country**: a tunnel whose exit country differs (for example,
  the VPN reconnected to another server) counts as failed for this policy.
* **Leak protection** toggles, below.

Policies are evaluated top to bottom; the first match wins.

## Domain rules

One rule per line:

| Rule | Matches |
|---|---|
| `example.com` | `example.com` and every subdomain |
| `.example.com` | subdomains only, not `example.com` |
| `=example.com` | exactly `example.com` |
| `*.example.com` | `*` = any text within one label: `a.example.com`, not `a.b.example.com` |
| `**.example.com` | `**` = any text across labels: `a.example.com`, `a.b.example.com` |
| `cdn-?.example.com` | `?` = one character (not a dot) |
| `api-*.*.example.com` | wildcards can appear anywhere |
| `~nflx` | any name containing `nflx` |
| `/^ipv4-c\d+-.*\.oca\.nflxvideo\.net$/` | RE2 regular expression, case-insensitive (`re:...` also works) |
| `!=ads.example.com` | exclusion: any rule prefixed with `!` |
| `drop:ads.example.com` | **block**: any domain rule after `drop:` (`drop:**.tracker.net`, `drop:~adserver`, `drop:/re/`) |
| `drop:asn:1234`, `drop:cidr:198.51.100.0/24` | **block** an autonomous system or an address range / single IP (`drop:ip:` also works) |
| `session:**.akamaized.net` | **device session**: any domain rule after `session:`; its answers are routed only for the device that looked the name up ([below](#device-sessions)) |
| `session[ttl=10m;onlookup=1]:x.example` | session with [options](#session-options) |
| `drop[share=kids]:ads.example.com` | **drop session**: blocked only for the device that looked the name up, plus the `share=` devices ([options](#session-options)) |
| `if:netflix.com;then:route:**.akamaized.net;else:drop:**.akamaized.net` | **conditional rule**: route or drop sessions per device ([below](#conditional-rules-if-then-else-finally)) |
| `com` | rejected: a bare top-level domain would route everything (`**.com` if you really mean it) |
| `# comment` | ignored; a trailing ` # comment` is allowed too (except in regexes) |

* **Connections keep their route.** Only new connections are matched against
  policies. A connection that started on WAN stays on WAN when its
  destination later joins a policy set (shared CDN addresses are answered for
  many names), because moving it would send its WAN NAT binding into the
  tunnel and stall it. The next connection to that address follows the
  policy. Failover clears policy connections so they move to the new tunnel. A connection that went into a tunnel is recognised by its NAT address
  (the tunnel's own address), so it stays in the tunnel even if another
  firmware component rewrites its conntrack mark.
  Accelerated packets reported as INVALID or UNTRACKED keep their existing
  route too; only NEW connections are evaluated against policy destinations.
  Existing WAN connections are recognised by their NAT address before marks
  are restored: firmware can overwrite a WAN connection mark with bits that
  look like a VPN policy, even with Adaptive QoS disabled.
* **Exclusions** veto a policy for that answer. A later policy can still match it.
* **Drop rules** block instead of route. DNS still answers, but the answered
  addresses go into the policy's drop set (`SNK_<id>_x4/6`; `drop:asn:` and
  `drop:cidr:` ranges go into `SNK_<id>_z4/6`), and the router rejects
  connections to them from the policy's devices, or from the whole LAN for a
  destination-only policy. TCP gets a reset and other traffic an ICMP error,
  so apps fail at once instead of timing out. This applies on IPv6 too, even
  when the policy leaves IPv6 alone.
  * Within a policy, `!` exclusions come first, then drop rules, then include
    rules: `drop:ads.example.com` blocks `ads.example.com` even if
    `example.com` routes the rest, and `!=ok.ads.example.com` still exempts
    that one name. `!drop:...` is an error; write the plain `!` rule.
  * Drop rules do not change what a policy routes: a whole-device policy with
    only `drop:` lines still routes the whole device.
  * Blocking is by address. A CDN address shared by a dropped name and an
    allowed one is blocked for both.
  * Plain `drop:` domains are also handled by dnsmasq; wildcards, keywords,
    regexes and CNAME matches need the DNS inspector.
* **CNAME chains**: when on (the default, per-policy toggle), a rule also
  matches when any name in the answer's CNAME chain matches. For example,
  `play.partner.tv → x1.cdn.nflxvideo.net` is caught by `**.nflxvideo.net`, and
  `**.akamaized.net` catches services that CNAME into Akamai.
* **Resolve via tunnel** applies to each rule's literal suffix: `nflxvideo.net`
  for `**.nflxvideo.net`, `oca.nflxvideo.net` for the regex above. Keywords and
  unanchored regexes have no suffix, so their DNS is resolved normally.

The policy editor has a live checker that flags bad lines and tests a name
against the rules. *Diagnostics → Test a domain* shows the real CNAME chain and
which rule matched.

## Rule files and rule lists

Rules can live in **rule lists**: named, reusable `.rules` files that any
number of policies include. A policy's own rules and those of all its lists
are merged. An exclusion anywhere applies to the whole policy.

```
# snake rules v1
@name Netflix
@description Netflix streaming
@source https://example.com/netflix.rules

# domains
netflix.com
**.nflxvideo.net
/^ipv4-c\d+-.*\.oca\.nflxvideo\.net$/
!=ads.netflix.com

asn:2906
cidr:23.246.0.0/18
ip:198.38.96.1
```

| Line | Meaning |
|---|---|
| domain rule | anything from the table above |
| `asn:2906` / `asn:AS2906` | all prefixes announced by that AS |
| `cidr:1.2.3.0/24`, `ip:1.2.3.4` | address range or single address |
| `@name`, `@description`, `@source` | list metadata; `@source` enables *Refresh* |
| `# ...` | comment (kept) |

**Import** from a file or a URL, in the web UI (*Rule lists* tab, or *Import
file* in a policy's rules editor) or with `snake rules import`. Lines from
other list formats are converted:

| Format | Example | Becomes |
|---|---|---|
| AdGuard / AdBlock | `\|\|example.com^` | `example.com` |
| hosts | `0.0.0.0 example.com` | `=example.com` |
| dnsmasq | `server=/a.com/b.com/1.1.1.1`, `ipset=/a.com/SET` | `a.com`, `b.com` |

Invalid lines are skipped and reported.

**Export** a list or a policy (with or without its lists inlined) as a
`.rules` file.

**Editor.** Both the *Rule lists* tab and the policy editor use a built-in
editor for the format:
* syntax highlighting (wildcards, regexes, exclusions, ASNs/CIDRs, directives, comments)
* line numbers, with errors and warnings marked in the gutter and listed below (click to jump)
* live validation as you type, with a summary of rule kinds and counts
* a *test a name* box showing which rule matches or which exclusion vetoes
* *Tidy* (canonical formatting and de-duplication), import/append file, export
* Ctrl/Cmd+S to save, Tab inserts spaces

CLI:

```
snake rules list
snake rules check netflix.rules                  # file:line: error ... (exit 1 on errors)
snake rules import netflix.rules [--name NAME]   # or a URL; --no-convert to disable conversion
snake rules export Netflix -o netflix.rules
snake rules export --policy "Netflix US" --expand
```

### How matching works

* **Plain domain rules** (`example.com`) are also written as dnsmasq
  `ipset=` lines. They keep working even if the daemon is down.
* **The DNS inspector** handles everything else (and CNAME chains). It reads
  dnsmasq's UDP answers to LAN clients from an NFQUEUE on the router's OUTPUT
  path, matches every name in the answer, and adds the A/AAAA addresses to the
  first matching policy's set. Only then does it release the answer, so the
  client's first connection is already routed.
* **Latency.** Every DNS answer to the LAN passes through the inspector, so
  it is built to stay out of the way of names no policy routes:
  * Plain domain rules (`example.com`, `.example.com`, `=example.com`) are
    looked up in a hash index by the name and its parent domains. Only
    wildcards, keywords and regexes are tested one by one. 20,000 rules cost
    microseconds per answer.
  * Answers that need no set change are released immediately. Answers with
    new addresses are handled by a pool of workers, so a slow update never
    holds up other lookups.
  * Set entries are added over netlink (tens of microseconds) instead of by
    running the `ipset` tool (milliseconds). If the kernel rejects that,
    snake falls back to the tool; Status shows *ipset netlink yes/no*.
* **Fail-open queue**: if the daemon stops, answers pass straight through.
* **Exclusions disable the dnsmasq fast path** for a policy, because dnsmasq
  cannot honour them.
* **Without NFQUEUE** in the kernel, only plain domain rules work (exclusions
  are ignored). Status and the leak audit say so.
* **TCP DNS answers** are not inspected. Clients use UDP unless an answer is
  truncated.

## Leak protection

| Toggle | What it does |
|---|---|
| Resolve via tunnel | `server=/domain/<resolver>` in dnsmasq, and an `ip rule` sends the router's queries to that resolver through the policy's tunnel. CDNs then pick servers near the VPN exit, not near you. The router can talk to the resolver in plain DNS, **DNS over TLS** or **DNS over HTTPS** (see below). |
| Hijack DNS | Redirects port 53 from scoped clients to the router, so devices with hardcoded DNS (e.g. `8.8.8.8`) are still seen by dnsmasq. |
| Block DoH | Rejects TCP/UDP 443 to the dedicated addresses of known DoH resolvers (8.8.8.8, 1.1.1.1, Quad9, AdGuard, NextDNS, ...). When DoH is blocked for the whole LAN (a destination-only policy, or Settings → *Always*), DoH hostnames such as `dns.google` also get NXDOMAIN from dnsmasq, so browsers fall back to normal DNS. Addresses are never learned from DNS answers: names like `dns.google.com` share addresses with ordinary Google sites, and blocking those cut Google downloads. Also answers the Firefox and iCloud Private Relay canary domains with NXDOMAIN (network-wide, Settings → *DoH canary*). |
| Block DoT | Rejects port 853 (DoT/DoQ), so Android "Private DNS" falls back to normal DNS. |
| Block QUIC | Rejects UDP 443 (optional). |
| Route HTTPS by server name | HTTPS connections no set matched go through snake's transparent SNI proxy, which routes them by the name in the TLS ClientHello. Lets devices keep DoH/DoT. See below. |
| IPv6 | *tunnel*: route IPv6 through the tunnel if it has IPv6, else reject IPv6 policy traffic so clients fall back to IPv4. *block*: always reject. *off*: untouched. |
| WebRTC | See below. |

**Settings → DNS** can override *Block DoT* and *Block DoH* router-wide, each
on its own: *Per policy* (the toggles above), *Always* (blocked for every
device on the LAN, whatever the policies say) or *Never* (allowed everywhere;
devices that use it bypass snake's domain rules).

"Scoped clients" means the policy's devices. For destination-only policies it
means the whole LAN, because any device might reach those destinations.
"The LAN" includes the clients of the router's own VPN servers, below.

### VPN server clients

Clients connected to the router's VPN servers are covered like LAN devices.
*Settings → Client interfaces* (`lan_interfaces`) lists the iptables
interface patterns snake treats as clients; the default is
`br+ wgs+ tun2+`:

| Pattern | Clients |
|---|---|
| `br+` | LAN, guest networks, and OpenVPN servers in TAP mode (bridged into br0) |
| `wgs+` | WireGuard server peers (`wgs1`, default subnet 10.6.0.0/24) |
| `tun2+` | OpenVPN servers in TUN mode (`tun21` 10.8.0.0/24, `tun22` 10.16.0.0/24) |

Configurations from before this version that still had the old default
(`br+`) are moved to the new one; a customised value is kept. Remove a
pattern to leave those clients alone.

For VPN server clients:

* Destination-only policies, leak protection, DNS inspection and the SNI
  proxy apply to them like to any LAN device.
* They have no MAC address at the router, so device-scoped policies select
  them by **IP address or subnet**: `10.6.0.2` for one WireGuard peer,
  `10.8.0.0/24` for every client of an OpenVPN server. The device picker
  lists WireGuard peers and OpenVPN client subnets from the router's
  settings. An address only matches its own family: add a peer's IPv6
  address too if it has one, or its IPv6 traffic is not matched (set the
  policy's IPv6 to *block* to make it fall back to IPv4).
* DNS hijacking DNATs their port-53 traffic to the router's LAN address
  (dnsmasq may not listen on the VPN server's own address). IPv6 DNS of VPN
  clients is not hijacked.
* The VPN server must let its clients reach the Internet (*Client access:
  LAN + Internet* / *Internet only*), or the firmware drops their traffic
  before it can be routed into a tunnel.

### Encrypted DNS through the tunnel

With *Resolve via tunnel* on, pick how the router talks to the policy's
resolver:

| Protocol | What goes through the tunnel |
|---|---|
| Plain DNS (default) | UDP/TCP 53. The tunnel encrypts it on your ISP link; the resolver's network sees it in clear. |
| DNS over TLS | TLS to `<resolver>:853` (RFC 7858). |
| DNS over HTTPS | HTTPS POST to `https://<name><path>` at `<resolver>:443` (RFC 8484). |

Plain DNS stays in the router's dnsmasq, which binds its upstream queries
to the selected tunnel interface. Snake does not start a plain-DNS listener.

For DoT and DoH the daemon runs a small forwarder per policy on loopback.
`dns_forward_port + policy id` is a preferred port; mDNS port 5353 and occupied
UDP/TCP ports are skipped automatically. Status shows the actual listener.
Only successfully bound endpoints are published to dnsmasq. If a listener
cannot start, its policy domains are handled locally without forwarding;
other policies continue to work.

The forwarder dials the resolver **by IP**, with a socket mark selecting
the policy's active tunnel, so no bootstrap lookup is needed. Multiple policies
may use the same resolver IP through different tunnels; ordinary router DNS
traffic to that resolver is not diverted. The certificate is checked against *Certificate name*, which is filled
in for well-known resolvers (Quad9, Cloudflare, Google, AdGuard, OpenDNS,
Mullvad). Connections are reused, and the Status tab shows queries, latency
and errors per policy.

If the resolver can't be reached, lookups for those domains fail with
SERVFAIL. They never fall back to plain DNS. While the daemon is stopped,
those domains don't resolve (the watchdog restarts it within 5 minutes; *Emergency
disable* removes the dnsmasq lines). Other domains keep using the router's
normal DNS settings.

### Routing HTTPS by server name (SNI sniffing)

Domain rules normally work by watching the router's DNS answers. A device
using DNS over HTTPS or DNS over TLS hides its lookups, which is why the
policies block DoH and DoT by default. With *Route HTTPS by server name* on,
the policy's domains are also recognised in the connections themselves, so
DoH/DoT can stay allowed (Settings → DNS → *Never*, or the policy toggles
off).

How it works:

* New TCP 443 connections from the policy's devices (the whole LAN for a
  destination-only policy) that **no policy claimed** (not in a set, not a
  routed device) are REDIRECTed to a proxy in the daemon
  (`sni_proxy_port`, default 5340). Connections the kernel already routes
  never touch it.
* The proxy reads the TLS ClientHello, which carries the server name (SNI)
  in clear text, and matches it against the domain rules (wildcards,
  regexes, keywords, exclusions, `drop:`). Nothing is decrypted: the bytes
  are relayed unchanged and the client verifies the real certificate.
* It dials the original destination itself. On a match the socket carries
  the policy's fwmark, so the policy's routing table applies: the active
  tunnel, the kill switch, or WAN when the policy has neither. Anything else
  is dialled without a mark and leaves via WAN as before. A `drop:` match
  resets the connection.
* A matched destination is added to the policy's domain set (as a DNS answer
  would be), so later connections to it, including QUIC, take the fast
  kernel path, and a WebRTC session window is opened for the client.

What it costs and where it stops:

* **Router CPU.** Every unclaimed HTTPS connection of those devices is
  terminated on the router and relayed (with `splice`, so data stays in the
  kernel). Expect lower throughput than the kernel path and no hardware
  acceleration for those connections; for a destination-only policy that is
  most of the LAN's HTTPS. Prefer device-scoped policies.
* **QUIC.** HTTP/3 hides its server name in an encrypted Initial packet, so
  UDP 443 that no policy claimed is **rejected** for those devices. Browsers
  fall back to TCP within a moment, which is then sniffed. QUIC to policy
  destinations still goes through the tunnel.
* **Encrypted Client Hello (ECH)** encrypts the real server name behind a
  public one (e.g. `cloudflare-ech.com` for every ECH site on Cloudflare).
  Each policy chooses what happens to its devices' ECH connections
  (*Encrypted Client Hello* in the policy editor, `ech` in the config):

  | Mode | What happens |
  |---|---|
  | **Relay** (`relay`, default) | Routed by the **public name** like any other connection: add it to the policy (`cloudflare-ech.com`) to send them through its tunnel, which then carries all ECH traffic to that CDN, or leave it out and they go via WAN. `drop:` rules for the public name apply. Once the destination is learned, other connections to that CDN address follow it too. |
  | **Drop** (`drop`) | **Reset**, so a hidden name cannot get past the policy's `drop:` rules. Browsers using DoH do not retry without ECH, so sites behind ECH-enabled CDNs (much of Cloudflare) stop loading on those devices. ECH adds no risk to the router or the network: only choose this if you rely on `drop:` rules for blocking. |
  | **Passthrough** (`passthrough`) | **Left alone**: relayed via WAN untouched. The policy does not route them by the public name and its `drop:` rules do not apply to them. |

  When several policies cover a device, one set to Drop is enough to reset
  its ECH connections. Otherwise only its Relay policies route them by the
  public name, in policy order; Passthrough policies are skipped. The Status
  tab counts ECH connections, and how many were dropped or passed through.
  Older configs convert by themselves: `refuse_ech: true` becomes Drop,
  anything else Relay (`refuse_ech` is kept in step for older versions).
* **Only TLS on port 443.** Other ports, plain HTTP, and non-TLS protocols
  on 443 (sent via WAN after 5 seconds of silence) are not routed by name.
* **IPv6** is sniffed only when `ip6tables` has NAT. Without it, IPv6 HTTPS
  of devices using encrypted DNS bypasses the domain rules (the leak audit
  says so).
* **Daemon down.** The redirect is removed when the daemon stops normally.
  If it crashes, HTTPS from those devices fails until the watchdog restarts
  it (within 5 minutes) or a firewall restart re-applies the rules without
  it.

## Device sessions

A **session** is one device + one address that a policy routes for that
device only. Two things start sessions:

* **`session:` rules**: when a device looks up a name a `session:` rule
  matches (e.g. `session:**.akamaized.net`), the answered addresses are
  routed through the tunnel **for that device only**. They are not added to
  the policy's sets, not saved, and not handed to dnsmasq. The DNS inspector
  holds the answer until the route is in place, so the device's first
  connection already uses the tunnel. The SNI proxy does the same when it
  sees a connection matching a `session:` rule by its TLS server name.
* **WebRTC peers** revealed by a device's STUN during its session window
  ([WebRTC](#webrtc)).

A session lasts **`session_ttl`** (Settings, default 600 s) **after the
device's last connection** to the address: the daemon renews every session
that still has a live connection (it scans `/proc/net/nf_conntrack` every
20 s, which also sees hardware-accelerated flows), so the countdown only
starts once the last connection closed, and a new connection within the TTL
renews it. After it ends, the device's next lookup starts a new one.

* Precedence within a policy: `!` exclusions, then `drop:`, then
  `session:`, then plain rules. So `session:` narrows routing:
  `example.com` plus `session:cdn.example.com` routes `cdn.example.com`
  only per device.
* Use it for shared CDN names: routing a CDN's addresses for every device
  would also send other sites on those addresses through the tunnel, for
  everyone.
* `session:` rules need the DNS inspector (NFQUEUE). Sessions follow the
  policy's devices and excluded devices, and appear in **Learnings →
  Policy addresses** (kinds *Sessions* and *WebRTC peers*), where they can
  be ended. **Flush learned** ends a policy's sessions.
* Each policy has a session chain `SNAKE_Q<id>` with one rule per device +
  address (at most 4096 per policy), rewritten as sessions start and end.

### Session options

`CMD[SETTING=VALUE;SETTING=VALUE;...]:` sets options on `session:`,
`route:` and `drop:` rules:

| Option | Meaning |
|---|---|
| `ttl=TIME` | this rule's session lifetime instead of `session_ttl`: seconds, or `90s`, `10m`, `1h` (10 s to 7 days) |
| `onlookup=0\|1` | `0` (default): the TTL counts from the device's last connection to the address. `1`: it counts from the lookup that started the session; a new lookup renews it, open connections do not |
| `share=VALUE` | also route the session for other devices; repeat it for a list (`share=A,share=B`). `global`: every device the policy covers; a **device group** name (`kids`, or `group:kids`); or a **device**: IP address, subnet or MAC. The shared copies start, renew and end with the session, and a live connection from a shared device (one given by address; `global` counts any device) keeps it alive |

Options are separated by `;` or `,`.

**Drop sessions.** A `drop:` rule with options (`drop[...]:`, domain rules
only) blocks per device instead of for everyone: when a device looks up a
matching name, the answered addresses are rejected for **that device** (and
the `share=` devices), and other devices still reach them, e.g. another site
on the same CDN address. A blocked device cannot keep a connection open, so
its TTL counts from its **last blocked attempt** (read from the rule's
packet counters) or, with `onlookup=1`, from the lookup. Plain `drop:`
without options keeps blocking for all the policy's devices. Drop sessions
use a filter chain per policy (`SNAKE_D<id>`) and are listed with the
sessions.

```
session[ttl=2m;onlookup=1]:**.example.org
route[ttl=30m]:**.akamaized.net;if:netflix.com
# the whole living room gets the CDN once one device starts Netflix
route[share=living-room,share=10.6.0.2]:**.nflxvideo.net;if:netflix.com
```

### Conditional rules (`if:`, `then:`, `else:`, `finally:`)

```
if:COND;then:ACTION;else:ACTION;finally:ACTION
```

`else:` and `finally:` are optional. Each **ACTION** is `route[options]:EXPR`
(the names' answers start [sessions](#device-sessions) through the tunnel
for the device) or `drop[options]:EXPR` (they start [drop
sessions](#session-options): blocked for that device). Options are those of
`session[...]`: `ttl`, `onlookup`, `share`.

* Names matching the **`if:`** condition are routed like plain rules, for
  every device, and snake remembers which addresses they resolved to.
* When a device looks up a name of a branch, the condition is evaluated
  **for that device, at that moment**: an `if:` name counts when the device
  has a **live connection** to one of its addresses (from the kernel's
  connection table).
  * Condition holds: `then:` names get `then:`'s action.
  * Condition does not hold: `else:` names get `else:`'s action.
  * Either way, `finally:` names get `finally:`'s action, checked after the
    branch: a name in both uses the branch.
  * A name no applicable part has is not routed by this rule.
* The latest decision for a device and address wins: a route session
  replaces a drop session for the same address and vice versa (e.g. when the
  device opens the `if:` site after a blocked lookup).
* A plain `route[options]:EXPR` (no `if:`) always starts sessions: `session:`
  with expressions.

Expressions combine domain rules (`example.com`, `.sub`, `=exact`, globs,
`~keyword`, `/regex/`) with modifiers, nested freely:

| Modifier | Meaning |
|---|---|
| `not:X` | X does not hold |
| `and:(X, Y, ...)` | all hold |
| `or:(X, Y, ...)` | any holds |
| `(X, Y, ...)` | same as `and:` (`(X)` just groups) |

In an action an expression tests the looked-up name; in `if:` each domain
rule stands for "the device has a live connection to an address of a name it
matches". Only the non-negated `if:` rules are routed; negated ones are
still watched. A rule may span lines: it continues after a line ending in
`;`, before a line starting with `;`, `then:`, `else:` or `finally:`, and
while parentheses are open.

```
# Netflix video through the tunnel while the device is on netflix.com,
# blocked otherwise; the help site is routed either way.
if:netflix.com;
then:route[ttl=10m]:or:(**.akamaized.net, **.nflxvideo.net);
else:drop:**.nflxvideo.net;
finally:route:=help.netflix.com

# Akamai addresses, per device, while it is on Disney+ or Hulu
if:or:(disneyplus.com, and:(hulu.com, not:=help.hulu.com))
then:route[ttl=5m]:(**.akamaized.net, not:=ads.akamaized.net, and:(not:~ads, ~cdn))
```

* Precedence within a policy: `!` exclusions, `drop:`, `session:`, `if:`
  names, branch names, then plain rules.
* The condition is checked when the branch name is looked up. If a page
  looks it up at the same moment as the `if:` site, before any connection
  to that site exists, that lookup gets the `else:` branch; the next one
  after the connection opened gets `then:`.
* Addresses count for an `if:` rule for 24 h after the last answer that gave
  them. Conditional rules need the DNS inspector; the SNI proxy applies them
  to connections by server name too.
* **Older form.** `route[options]:EXPR;if:COND` was replaced. Saved
  configurations and imported rule files are rewritten on load to
  `if:COND;then:route[options]:EXPR` (same behaviour); typing the old form in
  a new rule is rejected with the new form in the message.

## WebRTC

WebRTC media goes to peer or TURN addresses that never show up in DNS, so
domain matching cannot catch it. Routing *all* STUN through a tunnel would
break every other app's calls. snake tracks it per policy instead:

1. **Session window.** When a device opens a connection to a policy
   destination, its IP enters a short-lived `SNK_<id>_s` set (default 120 s).
   The daemon keeps the window open while the device still has live
   policy-marked connections, by scanning `/proc/net/nf_conntrack`. This keeps
   working even when hardware acceleration offloads the flows.
2. **STUN learning (NFQUEUE).** While the window is open, new UDP flows from
   that device go to the daemon over NFQUEUE (header only, fail-open).
   * If the packet is a STUN message, it is re-injected with the policy mark,
     so the whole flow, including its NAT binding, uses the tunnel from the
     first packet. Its destination is learned:
     * **ICE connectivity checks** (binding requests carrying `USERNAME`,
       `PRIORITY` or `ICE-CONTROLLING/CONTROLLED`) and anything ambiguous
       start a [device session](#device-sessions) with the peer: it is
       routed for that device only, until `session_ttl` after its last
       connection to the peer (an ongoing call keeps it). Older versions
       kept peers in a policy-wide set (`SNK_<id>_r`, `peer_timeout`); that
       set is removed on upgrade and `peer_timeout` is no longer used.
     * **Server requests** (plain binding requests, i.e. server-reflexive
       candidate gathering, and TURN Allocate/Refresh/CreatePermission/
       ChannelBind/Send) are learned into a **learning group** (see below).
       A request to a server that is already in a group uses that group's
       routing instead of the session's policy.
   * Anything else passes through untouched.
3. **Learning groups (pre-session coverage).** Browsers often start
   gathering ICE candidates before the page's first connection to a policy
   destination, and that early binding request would reveal the WAN address.
   Learned STUN/TURN servers are therefore kept in groups that are not tied
   to the policy that found them, and are routed through a policy of your
   choice **even outside a session**. See [Learnings](#learnings).
4. **Fallback.** If the kernel has no NFQUEUE, only STUN/TURN ports
   (`3478,3479,5349,19302:19309`) from devices inside a window are routed.
   There is no server learning in this mode, but learning groups routed via
   the policy still apply.

WebRTC from other apps, or from the same device outside a session, stays on WAN,
except UDP to STUN/TURN servers of learning groups routed via the policy.

## Learnings

The **Learnings** tab lists the learning groups. A group is created when a
device in a policy session contacts a STUN/TURN server that no group knows
yet. Every other new server the same device discovers during that session
window (kept open while the device has live policy connections) joins the
same group, so a service's STUN and TURN servers usually end up together. A
request to a server that is already known refreshes its group instead.

Each group records the sessions that were active when it was discovered:
every policy whose session window held the device, the tunnel each was
using, the device (IP, MAC, name) and up to five policy destinations the
device was connected to, named from the DNS inspector when it has seen them.

| Setting | Effect |
|---|---|
| Route via | Policy whose tunnel the group's servers use. It starts as the policy whose session discovered the group. *Off* sends them to WAN. Servers are routed for that policy's devices (the whole LAN for destination-only policies), even before a session starts, and UDP to one opens the device's session window so the ICE checks that follow are learned too. If the policy is deleted, disabled or has WebRTC tracking off, the servers are left alone and follow whatever session they show up in. |
| Enabled | Off: the group's servers go to WAN, also inside policy sessions. |
| Idle TTL | Each learned server is dropped once it has had no STUN request and no connection (any conntrack entry, checked every 20 s) for this long. Default: `stun_server_ttl` (1 day). |
| Pin | Nothing in the group expires. |
| Name, notes | Free text. A group you renamed or annotated is kept when its servers expire. |

You can also add addresses by hand (they never expire), remove them, move
them between groups, merge groups and delete groups. An address belongs to
one group at most.

### Policy addresses

The tab's second view lists the addresses each policy has learned:

* **DNS answers** (`SNK_<id>_d4/6`): for each address, the name that was
  resolved (and the CNAME that matched), the rule that matched and whether
  it comes from the policy or a rule list, the device the answer went to,
  when it was last answered and how often. These details are recorded by
  the DNS inspector and saved in `dnslearn.json`. Without the inspector
  (no NFQUEUE), dnsmasq still fills the set and the view shows the kernel
  contents without details. A per-rule summary lets you remove everything
  a rule learned.
* **WebRTC peers** (`SNK_<id>_r4/6`), with the time left before they expire.

Removing an address takes it out of the kernel set; the policy learns it
again on the next DNS answer or ICE check. To stop routing a domain,
change the rule.

### CLI

```
snake learn list                            # groups
snake learn show 3                          # servers + discovery sessions
snake learn new "Discord" --route "Netflix US" 162.159.135.234
snake learn set 3 --name Discord --route off --pin --ttl 12h --notes "voice"
snake learn add|rm 3 ADDR...
snake learn move 3 4 ADDR...
snake learn merge 3 4
snake learn delete 3
snake learn addrs "Netflix US" [--kind dns|peer] [--filter nflxvideo]
snake learn forget "Netflix US" ADDR... | --rule "**.nflxvideo.net" | --all
```

`--ttl` takes seconds, a duration (`12h`) or `default`; `--route` takes a
policy name or id, or `off`. `list`, `show` and `addrs` accept `--json`.

### Storage and API

Groups live in `learnings.json` next to `config.json`, saved on every
discovery and edit. The daemon installs each policy's share into
`SNK_<id>_t4/6`. API: `GET/POST /api/learnings`,
`PUT/DELETE /api/learnings/{id}`, `POST /api/learnings/{id}/servers`
(`{"add":[…],"remove":[…]}`), `/move` (`{"servers":[…],"to":id}`) and
`/merge` (`{"into":id}`). Policy addresses: `GET /api/learned/{policy}?kind=dns|peer&q=&limit=`
and `POST /api/learned/{policy}/forget`
(`{"kind":…,"addrs":[…]}`, `{"rule":…}` or `{"all":true}`).

## Failover

Each tunnel used by an enabled policy is checked every `health_interval`
seconds (default 15):

* Interface exists and is up. For WireGuard, the latest handshake is newer than
  `handshake_max_age`. For the firmware's OpenVPN clients,
  `vpn_clientN_state` is 2 (connected); snake's own (`ovxN`) rely on the
  probes below.
* TCP connects to `probe_targets` **through the tunnel**. The sockets carry a
  per-tunnel probe fwmark routed by a table with an unreachable fallback, so a
  dead tunnel can never look healthy via WAN. After `probe_failures`
  consecutive failures, the tunnel is down.
* Exit IP and country are fetched through the tunnel (`geo_url`, default
  ipinfo.io). This happens every `geo_interval` and whenever a tunnel recovers.

If the active tunnel fails, the policy switches immediately to the
highest-priority usable one. With auto fail-back on, it returns to a better
tunnel once that tunnel has been healthy for `failback_hold` seconds.

Route changes use `ip route replace` and add-before-delete rule
reconciliation, so traffic never falls through to WAN mid-update. Conntrack
entries of the policy are flushed when the `conntrack` tool exists.

## How it works

```
LAN client ──► mangle PREROUTING -i br+/wgs+/tun2+ ─► SNAKE
                 WAN/tunnel NAT affinity, then isolated connection policy │ private dst → RETURN
                 SNAKE_P<id> (in policy order):
                   mac / ipset(dnsmasq-learned, ASN+CIDR, WebRTC peers/servers)  ─► SNAKE_M<id>: MARK id<<16, save connmark
                 SNAKE_RTC: NFQUEUE for session clients' new UDP flows
            ─► ip rule  pref 5200+id  fwmark id<<16/0xc0ff0000 → table 1000+id
               table 1000+id: default dev <active tunnel> | unreachable (kill switch) | empty (→ main/WAN)
            ─► nat POSTROUTING SNAKE_NAT: MASQUERADE marked traffic out of tunnels
filter FORWARD SNAKE_FWD: DoT/DoH/QUIC/IPv6 rejects, then accept LAN⇄tunnel
nat PREROUTING SNAKE_DNS: port-53 REDIRECT; TCP 443 → SNAKE_SNI: unclaimed → REDIRECT to the SNI proxy
dnsmasq: ipset=/netflix.com/.../SNK_1_d4,SNK_1_d6   server=/netflix.com/9.9.9.9
mangle OUTPUT SNAKE_DNSO: dnsmasq's UDP answers → NFQUEUE → DNS inspector → SNK_<id>_d4/d6
```

* fwmark bits `0x00ff0000` (configurable, Settings → Advanced). Policy ids
  use bits 16-18, the Broadcom flow-id field that Merlin's VPN Director
  (`0xf000`) also uses. On Broadcom routers every mark bit has a vendor
  meaning: bits 24-31 (egress port, WAN flag, IPsec, policy routing) break
  routed traffic and are rejected. A short-lived version used `0x3fc00000`;
  configs with it are moved back automatically.
* Connection policy ownership uses `0x3fc00000`, separate from Adaptive
  QoS classification (`0xc03fffff`) and VPN Director (`0xf000`). Only these
  owned connection bits are changed; firmware classification is preserved.
  Packet routing requires the QoS direction bits clear, so QoS categories
  cannot match VPN rules. After routing, classified VPN packets regain
  their QoS packet mark for egress scheduling; NAT uses isolated connection
  ownership. Overlapping custom connection masks are rejected even when
  QoS is off, so enabling it later does not invalidate the configuration.
  Other addons must not claim snake's documented masks, tables or priorities.
* ip rule priorities 4980–5499, routing tables 1000–1350 (probe tables
  1301–1310 for the firmware clients, 1311–1330 for `wgx1`–`wgx20` and
  1331–1350 for `ovx1`–`ovx20`, whose probe rules use priorities
  5401–5440).
* All chains are loaded with `iptables-restore --noflush`, so each table is
  updated atomically. Chains of removed policies are deleted in the same
  transaction.
* Learned DNS sets are saved to `/jffs/addons/snake/ipsets.save` every 30
  minutes and on shutdown, so they're warm after a reboot. Domains are also
  pre-resolved at startup.

## Hooks

| Script | Action |
|---|---|
| `services-start` | mount web page, add watchdog cron, start daemon |
| `services-stop` | stop daemon (saves sets) |
| `firewall-start`, `nat-start` | re-apply rules (directly if the daemon is not up yet) |
| `dnsmasq.postconf` | include `/jffs/addons/snake/dnsmasq.conf` |
| `wgclient-start/stop`, `openvpn-event` | trigger an immediate health check |

The daemon also notices missing hooks (firewall restarted without running the
scripts) within 30 s and re-applies.

## CLI

```
snake status                 tunnels, policies, active routes
snake test www.netflix.com   which policy, which tunnel, are the IPs in the sets?
snake apply [--dry-run]      re-apply (dry run prints every command, touches nothing)
snake reload                 re-read config.json
snake policy list
snake rules list|check|import|export
snake import-dvr [--dir /jffs/configs/domain_vpn_routing] [--yes]
snake token [--rotate]       API token for the standalone UI at http://router:8444/
snake start | stop [--flush] | restart
snake disable | enable       emergency switch (see below)
snake update [--check]       install the latest release (see Updates and rollback)
snake rollback               go back to the version before the last update
```

### Emergency disable

The red **Emergency disable** button at the top of the web UI (or
`snake disable` over SSH) removes every rule, route, ipset and dnsmasq option
snake installed. The router then behaves as if snake were not installed: all
traffic goes over the normal WAN connection, and **kill switches and leak
protection stop working**. The daemon keeps running so the UI stays usable;
your configuration and learned addresses are kept. Firewall/tunnel hooks and
configuration saves do not re-apply anything while disabled.

The state is a flag file (`/jffs/addons/snake/disabled`), so snake stays
disabled across restarts and reboots until you press **Enable snake** or run
`snake enable`.

## Web UI and API

The Addons page is served by the router (behind its login). It talks to the
daemon's API on `http://<lan-ip>:8444`, or `https://...:8445` using the
router's certificate when the WebUI is on HTTPS. The API needs a bearer token
that only the logged-in Addons page can read (it lives in
`custom_settings.txt`). It listens on the LAN address only. The CLI uses a
root-only unix socket.

The Addons page is a narrow (760 px) column inside the firmware's layout.
**Open full page ↗** at the top opens the same UI on the daemon's own page
(`http://<lan-ip>:8444/`, or `https://...:8445/`), with room for every
control. It hands over the token in the URL fragment, which is not sent to
the server; the page stores it in the browser and removes it from the
address. The Addons page holds a copy of the UI: snake rewrites it on
install, at boot and after every update or rollback (`snake webui-mount`
does it by hand).

Diagnostics tab:
* **Test a domain**: which policy matches, resolved addresses, and whether each
  one is in a set.
* **Router-side leak audit**: per-policy checklist of what is and isn't
  protected.
* **Browser leak test**: HTTP exit IP and WebRTC (STUN) public IPs of the
  device you're browsing from, labelled as WAN / tunnel.
* Daemon logs and the generated firewall rules. Learned addresses are in the
  Learnings tab.

## Importing from Domain VPN Routing

Use **Import** in the UI, or `snake import-dvr`. It reads
`domain_vpn_routing.conf`, each policy's domain list and `asn.conf`:
* Policies on `wan` are skipped.
* Imported policies get full leak protection with the kill switch **off**.
  Review them.
* Then uninstall Domain VPN Routing so the two don't compete for the same
  traffic.

## Configuration

`/jffs/addons/snake/config.json` is edited by the UI. You can also edit it by
hand and run `snake reload`. See `testdata/config.json` for an example.

## Caveats

* Streaming services block known VPN/datacenter IP ranges. snake controls
  *routing and leaks*; whether your VPN exit is accepted is up to the provider.
  Residential or dedicated IPs work best.
* Domain matching only works when the router's dnsmasq does the resolving.
  Keep DNS hijack and DoH/DoT blocking on for destination policies (or
  turn on *Route HTTPS by server name*). Smart-TV
  apps that pin their own encrypted DNS are best handled with a whole-device
  policy.
* DoT blocking and DoH canaries in a destination-only policy apply to the whole
  LAN (by design: any device might be a client of that service).
* IPv6 needs the kernel IPv6 stack and `ip6tables` NAT. Without NAT support,
  IPv6 policy traffic is blocked rather than leaked.

## Development

Building needs Go 1.26 or newer (with the default `GOTOOLCHAIN=auto`, an
older `go` downloads it) and, for the web UI, Node.js 22.

The web UI is an [Astro](https://astro.build) + [React](https://react.dev) + [Tailwind CSS](https://tailwindcss.com)
project in `web/`:

* `web/src/pages/index.astro`: the page shell;
* `web/src/scripts/app.js`: the app, which renders the UI from the daemon's
  JSON API;
* `web/src/components/`: React components the app mounts in place
  (`src/scripts/react-bridge.js`): `DeviceSelector` (include/exclude
  devices, used for policies and for groups), `TunnelPicker` (failover
  order), `ChecklistPicker` (rule lists), and shared controls in
  `components/controls/` (`Button`, `Badge`/`TunnelHealth`, `SearchBox`,
  `FilterChips`, `SelectionToolbar`, `TriState`). React is compiled by
  Vite's React plugin; Astro's React integration is not used because its
  island runtime would add a second script, and the router page needs
  one. `npm test` runs the components' logic tests (`*.test.js`);
* `web/src/styles/global.css`: Tailwind theme and the UI's component
  classes. Utilities are prefixed (`tw:mt-2`, `tw:text-warn`) and there is no
  preflight reset, because the same CSS runs inside the router's own WebUI
  page.

`make web` builds it to a static page in `internal/webui/build/site` (not
committed), which the Go binary embeds. Its CSS and JS are inlined into the
standalone page and into the router's Addons page, which must be a single
file. `make arm64`, `make armv7` and `make test` build the UI first. A plain
`go build` without it still works; the binary then shows a "web UI not built"
notice instead of the UI.

Releases are built by GitHub Actions: push a tag like `v1.2.3` and
`.github/workflows/release.yml` builds the web UI, tests, builds `snake-arm64`
and `snake-armv7`, and publishes them with `SHA256SUMS` as a GitHub release.
Every push also builds the UI, runs tests and builds (`ci.yml`), and uploads
the binaries and the static page as artifacts.

```
make web           # build the web UI (npm ci when web/package-lock.json changed)
make test          # web UI build, JS + Go unit tests (fails if the UI is missing)
make integration   # real iptables/ipset/ip and OpenVPN in a throwaway netns (root)
make ui-dev        # UI against a fake engine at http://127.0.0.1:18444 (token "testtoken")
```
