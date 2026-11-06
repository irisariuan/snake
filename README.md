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
| Domain rules | domain list | suffix, exact, subdomains-only, `*`/`**`/`?` wildcards, `~keyword`, `/regex/`, `!exclusions`, CNAME-chain matching |
| Tunnels per policy | one | **ordered list with failover / fail-back** |
| Health | – | interface + WireGuard handshake / OpenVPN state, TCP probes *through* the tunnel, **exit-country check** |
| Tunnel down | traffic goes via WAN | **kill switch** (per policy) or WAN, your choice |
| Device scoping | – | whole device, or device + destinations, groups of devices |
| DNS leaks | – | policy domains resolved **through the tunnel**, port-53 hijack, DoH/DoT/QUIC blocking, DoH canaries |
| IPv6 | separate ipsets | routed via tunnel if it has IPv6, otherwise **blocked** for policy traffic |
| WebRTC | – | **session-affinity tracking** (see below) |
| Rule files | – | `.rules` files: import (file/URL, AdGuard/hosts/dnsmasq converted), export, reusable **rule lists**, built-in highlighting editor |
| UI | SSH menu | Merlin Addons page + CLI |

## Requirements

* Asuswrt-Merlin 386.x or newer (Addons API, `ipset`, `dnsmasq` with ipset support)
* One or more VPN clients configured in *VPN → VPN Client* (WireGuard `wgc1-5`
  and/or OpenVPN `ovpnc1-5`; mixing types in one failover list is fine)
* JFFS custom scripts (the installer turns them on)

In each VPN client you want snake to use, set **"Redirect Internet traffic
through tunnel" to "VPN Director"** and add *no* VPN Director rules. The tunnel
stays up but carries nothing until snake routes traffic into it.

## Install

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

Uninstall with `snake uninstall`. This removes rules, routes, sets, hooks and
the page; add `--purge` to delete the config too.

## Policies

A policy is:

* **Tunnels**, in priority order. The first healthy one is used. Later ones are
  failover backups.
* **Match**: [rules](#domain-rules) (domain rules, `asn:`, `cidr:`), [rule lists](#rule-files-and-rule-lists)
  it includes, and/or devices (MACs or groups).
  * destinations only → those destinations, for every device
  * devices only → the **whole device** (most reliable for TV apps)
  * both → those destinations, only for those devices
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
| `com` | rejected: a bare top-level domain would route everything (`**.com` if you really mean it) |
| `# comment` | ignored; a trailing ` # comment` is allowed too (except in regexes) |

* **Exclusions** veto a policy for that answer. A later policy can still match it.
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
| Resolve via tunnel | `server=/domain/<resolver>` in dnsmasq, and an `ip rule` sends the router's queries to that resolver through the policy's tunnel. CDNs then pick servers near the VPN exit, not near you. |
| Hijack DNS | Redirects port 53 from scoped clients to the router, so devices with hardcoded DNS (e.g. `8.8.8.8`) are still seen by dnsmasq. |
| Block DoH | Rejects TCP/UDP 443 to known DoH resolvers (static list plus dnsmasq-learned addresses of DoH hostnames). Also answers the Firefox and iCloud Private Relay canary domains with NXDOMAIN (network-wide, Settings → *DoH canary*). |
| Block DoT | Rejects port 853 (DoT/DoQ), so Android "Private DNS" falls back to normal DNS. |
| Block QUIC | Rejects UDP 443 (optional). |
| IPv6 | *tunnel*: route IPv6 through the tunnel if it has IPv6, else reject IPv6 policy traffic so clients fall back to IPv4. *block*: always reject. *off*: untouched. |
| WebRTC | See below. |

"Scoped clients" means the policy's devices. For destination-only policies it
means the whole LAN, because any device might reach those destinations.

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
       `PRIORITY` or `ICE-CONTROLLING/CONTROLLED`) and anything ambiguous go
       to the peer set `SNK_<id>_r` (`peer_timeout`, default 600 s). Peers are
       routed only for devices inside a session window.
     * **Server requests** (plain binding requests, i.e. server-reflexive
       candidate gathering, and TURN Allocate/Refresh/CreatePermission/
       ChannelBind/Send) go to the server set `SNK_<id>_t`.
   * Anything else passes through untouched.
3. **Learned servers (pre-session coverage).** Browsers often start gathering
   ICE candidates before the page's first connection to a policy destination.
   That early binding request would reveal the WAN address. Learned
   STUN/TURN servers are therefore routed through the tunnel for the policy's
   devices (the whole LAN for destination-only policies) **even outside a
   session**, and a new UDP flow to one opens the device's session window, so
   the ICE checks that follow are learned too.
   * Each server has a TTL (`stun_server_ttl`, default 86400 s). The session
     refresher re-arms it every 20 s while any policy-marked connection to
     the server is still in conntrack, so the countdown only starts once the
     server is idle. A server shared with unrelated apps (a public STUN
     server, for example) therefore drops out after a quiet period instead of
     staying tunnelled forever.
   * Server sets are saved with the DNS-learned sets (`save_interval`), so the
     coverage survives a reboot.
   * The first visit to a service still has no learned servers, so ICE
     gathering that starts before its first session can use WAN once.
4. **Fallback.** If the kernel has no NFQUEUE, only STUN/TURN ports
   (`3478,3479,5349,19302:19309`) from devices inside a window are routed.
   There is no server learning in this mode.

WebRTC from other apps, or from the same device outside a session, stays on WAN,
except UDP to a learned STUN/TURN server of the policy.

## Failover

Each tunnel used by an enabled policy is checked every `health_interval`
seconds (default 15):

* Interface exists and is up. For WireGuard, the latest handshake is newer than
  `handshake_max_age`. For OpenVPN, `vpn_clientN_state` is 2 (connected).
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
LAN client ──► mangle PREROUTING -i br+ ─► SNAKE
                 restore connmark │ private dst → RETURN
                 SNAKE_P<id> (in policy order):
                   mac / ipset(dnsmasq-learned, ASN+CIDR, WebRTC peers/servers)  ─► SNAKE_M<id>: MARK id<<16, save connmark
                 SNAKE_RTC: NFQUEUE for session clients' new UDP flows
            ─► ip rule  pref 5200+id  fwmark id<<16/0xff0000 → table 1000+id
               table 1000+id: default dev <active tunnel> | unreachable (kill switch) | empty (→ main/WAN)
            ─► nat POSTROUTING SNAKE_NAT: MASQUERADE marked traffic out of tunnels
filter FORWARD SNAKE_FWD: DoT/DoH/QUIC/IPv6 rejects, then accept LAN⇄tunnel
nat PREROUTING SNAKE_DNS: port-53 REDIRECT
dnsmasq: ipset=/netflix.com/.../SNK_1_d4,SNK_1_d6   server=/netflix.com/9.9.9.9
mangle OUTPUT SNAKE_DNSO: dnsmasq's UDP answers → NFQUEUE → DNS inspector → SNK_<id>_d4/d6
```

* fwmark bits `0x00ff0000` (configurable). These don't overlap Merlin's VPN
  Director (`0xf000`) or QoS bits.
* ip rule priorities 4980–5499, routing tables 1000–1310.
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
```

## Web UI and API

The Addons page is served by the router (behind its login). It talks to the
daemon's API on `http://<lan-ip>:8444`, or `https://...:8445` using the
router's certificate when the WebUI is on HTTPS. The API needs a bearer token
that only the logged-in Addons page can read (it lives in
`custom_settings.txt`). It listens on the LAN address only. The CLI uses a
root-only unix socket.

Diagnostics tab:
* **Test a domain**: which policy matches, resolved addresses, and whether each
  one is in a set.
* **Router-side leak audit**: per-policy checklist of what is and isn't
  protected.
* **Browser leak test**: HTTP exit IP and WebRTC (STUN) public IPs of the
  device you're browsing from, labelled as WAN / tunnel.
* **Learned set contents**, daemon logs, and the generated firewall rules.

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
  Keep DNS hijack and DoH/DoT blocking on for destination policies. Smart-TV
  apps that pin their own encrypted DNS are best handled with a whole-device
  policy.
* DoT blocking and DoH canaries in a destination-only policy apply to the whole
  LAN (by design: any device might be a client of that service).
* IPv6 needs the kernel IPv6 stack and `ip6tables` NAT. Without NAT support,
  IPv6 policy traffic is blocked rather than leaked.

## Development

```
make test          # unit tests
make integration   # real iptables/ipset/ip in a throwaway netns (root)
make ui-dev        # UI against a fake engine at http://127.0.0.1:18444 (token "testtoken")
```
