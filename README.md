# Wazuh Custom Decoders & Rules for Network Infrastructure

Custom Wazuh SIEM integration for **Ubiquiti UniFi (UDM Pro Max)**, **MikroTik RouterOS 7.x**, and **Fortinet FortiGate** devices, providing comprehensive log decoding, field extraction, noise suppression, and alerting rules.

Developed and tested on **Wazuh 4.14.3** by [Astier Consulting](https://www.astier-consulting.fr) — Apple/IT consulting with 30 years of datacenter management experience.

## Why this project?

When we set out to integrate our network infrastructure into Wazuh, we found that:

- The **BNC community rules** for UniFi (`0999-bnc-unifi-rules.xml`) are outdated and reference decoder names that no longer exist
- There were **no working decoders** for MikroTik RouterOS 7.x with BSD syslog format
- UniFi CEF events (WiFi client tracking, admin access) were **not decoded at all**
- Fortinet built-in decoders work well, but **without tuning, mDNS/Bonjour noise drowns out real alerts** — especially in Apple-heavy environments
- Documentation on Wazuh PCRE2 limitations was scattered and incomplete

This repository provides production-tested decoders and rules that actually work, along with noise suppression tuning for real-world mixed environments.

## Features

### MikroTik RouterOS 7.x
Custom decoders and rules — nothing usable existed for RouterOS 7.x BSD syslog.

- **Firewall**: DROP IPv4/IPv6, invalid forward, INPUT protection
- **DHCP**: Server operations (discover, offer, request, ack, lease, removal)
- **Authentication**: Login/logout with external IP detection
- **Correlation rules**: Port scan detection, brute force alerts
- **MITRE ATT&CK**: T1078 (Valid Accounts), T1133 (External Remote Services), T1110 (Brute Force)

### Ubiquiti UniFi (UDM Pro Max)
Custom decoders and rules — the existing BNC community rules are broken.

- **Firewall**: iptables rules with full field extraction (src/dst IP, MAC, ports, flags)
- **WiFi tracking**: Client connected/disconnected/roamed with enriched fields (device alias, AP name, SSID, band, RSSI, duration)
- **Protect**: Smart detection (person/vehicle/animal/license plate), camera motion, sensor motion, tamper, loiter, device disconnect, door sensor open/close, admin activity, intrusion correlation
- **OS**: Console access, application update notifications and tracking — covers the UniFi OS layer independently from Network and Protect
- **Audit trail**: Configuration changes (created/removed), software updates, console access — essential for DORA/compliance
- **DHCP**: Pool exhaustion alerts, lease tracking
- **Admin access**: Management interface access with MITRE mapping
- **Wired tracking**: Client connected/disconnected on switches with port and link speed details
- **Device management**: Firmware update alerts with version tracking
- **UPS monitoring**: Battery power and AC restore events with battery percentage extraction (level 10 critical alert)
- **Infrastructure alerts**: Poor AP link speed detection
- **Noise suppression**: ubios-udapi-server, DPI stats, system events filtered at level 0

### Fortinet FortiGate
Supplementary rules on top of Wazuh's built-in FortiGate decoders (which work well). The focus here is **noise suppression and VPN monitoring** — in environments with Apple devices, Bonjour/mDNS generates thousands of deny logs per minute that bury real security events.

- **mDNS/LLMNR suppression**: Filters out the massive volume of UDP/5353 and UDP/5355 deny logs typical in Apple/HomeKit/Bonjour environments
- **UniFi discovery suppression**: Filters UDP/10001 broadcast noise
- **VPN IPsec monitoring**: Alerts on denied traffic through site-to-site tunnels (routing issues, unauthorized access attempts). Filters on `action="deny"` to avoid false positives from legitimate ZTNA traffic
- **System events**: Performance stats, AV database updates, disk log rotation
- **Correlation**: Repeated VPN denies trigger higher-level alerts for investigation

## Architecture
```
MikroTik CCR2004 ──────┐
                        │
UniFi UDM Pro Max ──────┼──► Syslog UDP/514 ──► Wazuh Server (rsyslog → analysisd)
                        │
Fortinet FortiGate ─────┘
```

MikroTik and UniFi send BSD syslog format. FortiGate uses its native key=value syslog format. Wazuh's pre-decoder extracts timestamp and hostname before custom decoders process the message payload.

## Key technical learnings

These are hard-won lessons from building these integrations:

1. **Wazuh PCRE2: one child decoder per parent** — When multiple `<decoder>` children with `type="pcre2"` share the same `<parent>`, only the first one matches. Solution: create separate parent/child pairs for each log type.

2. **`[^\]]+` fails in Wazuh PCRE2** — Use explicit character classes like `[a-f0-9:]+` for IPv6 addresses instead.

3. **BSD syslog pre-decoder consumes the hostname** — Your decoder `<prematch>` must NOT include the device hostname (e.g., `MikroTik`), as it's already extracted by the pre-decoder.

4. **UniFi CEF `program_name` extraction** — When UDM hostname contains hyphens (`UDM-Pro-Max-AC`), the pre-decoder extracts `program_name: CEF`. Decoders must use `<program_name>^CEF</program_name>` to match.

5. **`<match>` vs `<field>` in rules** — `action` is a static decoded field. Use `<match>` to search the raw log, or `<decoded_as>` with specific decoder names for targeting.

6. **Rule hierarchy matters** — Use `<if_sid>` for child rules. Without it, catch-all rules at the same level may match before specific ones.

7. **Anchor all prematches with `^`** — Generic prematches like `lease ` can match unexpected content (e.g., "Please" contains "lease"). Always anchor with `^` to match only at the start of the decoded message.

8. **Fortinet noise in Apple environments** — A single Apple TV or HomePod can generate 2000+ mDNS deny logs per minute on a FortiGate. Use level 0 rules in Wazuh to suppress noise while preserving archives for forensics.

9. **Catch-all rules must be parents, not siblings** — When multiple rules share the same `<decoded_as>` without `<match>`, the catch-all (no `<match>`) wins unpredictably over specific rules. Solution: make the catch-all the parent rule, and specific rules its children via `<if_sid>`. This pattern is used for both UniFi Protect (100312 as parent) and Network CEF (100344 as parent).

10. **Avoid spaces in UDM hostname** — The BSD syslog pre-decoder splits on spaces. A hostname like `UDM Pro Max AC` gets truncated to `UDM`, breaking decoder matching for Protect events. Use hyphens instead: `UDM-Pro-Max-AC`.

11. **Decoder order matters across files** — Wazuh loads decoder files alphabetically. A catch-all decoder in `ubiquiti.xml` will match before specific decoders in `unifi.xml`. Place specific decoders (UPS, WiFi) in the same file as the catch-all, or ensure they load first.

12. **FortiGate VPN rule: always filter on action** — A rule matching `vpntype="ipsecvpn"` without `action="deny"` will flag all ZTNA/IPsec traffic (accept, close, client-rst) as "denied". Always combine VPN type with action filter.

## Installation

### 1. Copy decoders
```bash
cp decoders/mikrotik_custom.xml /var/ossec/etc/decoders/
cp decoders/ubiquiti.xml /var/ossec/etc/decoders/
# Only if you use UniFi Protect (CEF format):
cp decoders/unifi.xml /var/ossec/etc/decoders/
```

### 2. Copy rules
```bash
cp rules/mikrotik_rules.xml /var/ossec/etc/rules/
cp rules/unifi_rules.xml /var/ossec/etc/rules/
# Only if you have a FortiGate:
cp rules/fortigate_rules.xml /var/ossec/etc/rules/
```

### 3. Set permissions
```bash
chown wazuh:wazuh /var/ossec/etc/decoders/mikrotik_custom.xml
chown wazuh:wazuh /var/ossec/etc/decoders/ubiquiti.xml
chown wazuh:wazuh /var/ossec/etc/rules/*.xml
chmod 660 /var/ossec/etc/decoders/*.xml /var/ossec/etc/rules/*.xml
```

### 4. Disable conflicting BNC rules (if present)
Add to `/var/ossec/etc/ossec.conf` inside `<ruleset>`:
```xml
<rule_exclude>0999-bnc-unifi-rules.xml</rule_exclude>
```

### 5. Validate and restart
```bash
/var/ossec/bin/wazuh-analysisd -t
systemctl restart wazuh-manager
```

## Device configuration

### MikroTik RouterOS 7.x
```routeros
/system logging action add name=wazuh target=remote remote=<WAZUH_IP> remote-port=514 src-address=<ROUTER_IP> bsd-syslog=yes
/system logging add action=wazuh topics=firewall
/system logging add action=wazuh topics=dhcp
/system logging add action=wazuh topics=system
```

### UniFi UDM (via Network UI)
Navigate to **Settings → System → Activity Logging (Syslog)**:
- Select **SIEM Server**
- Server Address: `<WAZUH_IP>`
- Port: `514`
- Contents: Gateway, Access Points, Switches, Admin Activity, Clients, Security Detections, Triggers, Devices, Updates, VPN, Firewall Default Policy

> **Tip**: Avoid spaces in your UDM hostname (e.g., use `UDM-Pro-Max-AC` instead of `UDM Pro Max AC`). Spaces break the BSD syslog pre-decoder and cause Protect events to be misclassified.

### Fortinet FortiGate
The FortiGate should be configured to send syslog to your Wazuh server. No special format is needed — Wazuh's built-in decoders handle FortiGate's native key=value format. Our custom rules layer on top for noise suppression and enhanced alerting.
```
config log syslogd setting
    set status enable
    set server "<WAZUH_IP>"
    set port 514
    set facility local7
    set source-ip "<FORTIGATE_IP>"
end
```

### Wazuh Server (rsyslog)
Create `/etc/rsyslog.d/10-mikrotik.conf`:
```
$template MikroTikFormat,"/var/ossec/logs/MikroTik/%HOSTNAME%/messages-%$YEAR%-%$MONTH%-%$DAY%.log"
if $fromhost-ip == '<MIKROTIK_IP>' then ?MikroTikFormat
& stop
```

## Rule IDs

| Range | Device | Category |
|-------|--------|----------|
| 100200-100211 | MikroTik | Firewall (DROP, invalid, scan detection) |
| 100220-100223 | MikroTik | Authentication (login, brute force) |
| 100230-100233 | MikroTik | DHCP operations |
| 100240 | MikroTik | System catch-all |
| 100300-100302 | UniFi | Firewall (base, DROP, Allow suppressed) |
| 100310-100316 | UniFi | Protect (smart detect, camera/sensor motion, admin activity, intrusion correlation) |
| 100320-100321 | UniFi | DHCP (events, pool exhaustion) |
| 100330-100331 | UniFi | Noise suppression (services, DPI) |
| 100340-100349 | UniFi | WiFi, Wired, Network CEF, Device Updates, UPS power |
| 100350 | UniFi | System suppression |
| 100351-100355 | UniFi | Network audit & infra (console access, config changes, software updates, AP link speed) |
| 100360-100363 | UniFi | OS events (console access, application update available/completed) |
| 100400-100401 | FortiGate | Noise suppression (mDNS, UniFi discovery) |
| 100410-100411 | FortiGate | VPN IPsec (denied traffic, VPN events) |
| 100420-100422 | FortiGate | System (perf stats, disk rotation, AV updates) |
| 100430 | FortiGate | Correlation (repeated VPN denies) |

## Decoded fields

### MikroTik Firewall
| Field | Content | Example |
|-------|---------|---------|
| `srcip` | Source IP | `192.168.1.100` |
| `dstip` | Destination IP | `8.8.8.8` |
| `srcport` | Source port | `54321` |
| `dstport` | Destination port | `443` |
| `protocol` | Protocol | `TCP` / `UDP` |
| `action` | Firewall chain | `DROP` |

### UniFi WiFi (enriched)
| Field | Content | Example |
|-------|---------|---------|
| `srcip` | Client IP | `192.168.1.100` |
| `srcmac` | Client MAC | `aa:bb:cc:dd:ee:01` |
| `dstuser` | Device alias | `iPhone de Jean` |
| `extra_data` | Access Point | `AP-Bureau-RDC` |
| `system_name` | SSID | `MonSSID` |
| `protocol` | WiFi band | `6e` |
| `data` | RSSI or duration | `-41` / `2m` |
| `action` | Network name | `LAN` |

### UniFi UPS (enriched)
| Field | Content | Example |
|-------|---------|---------|
| `extra_data` | UPS device name | `UPS Bureau Cave` |
| `srcip` | UPS IP address | `192.168.0.40` |
| `data` | Battery remaining | `93.0%` |
| `action` | Full message | `UPS Bureau Cave has lost AC power...` |

### FortiGate (built-in decoder fields)
Wazuh's built-in FortiGate decoder extracts all native fields: `srcip`, `dstip`, `srcport`, `dstport`, `action`, `policyid`, `service`, `srcintf`, `dstintf`, `devname`, `logid`, `level`, and more. Our custom rules add context through enhanced descriptions that surface VPN tunnel names and traffic patterns.

## UniFi CEF Event IDs

These are the UniFi Network, Protect, and OS CEF event IDs we have identified and mapped:

| ID | Event | Source |
|----|-------|--------|
| 215 | UPS Battery Power In Use | Network |
| 216 | UPS AC Power Restored | Network |
| 400 | WiFi Client Connected | Network |
| 401 | WiFi Client Disconnected | Network |
| 402 | WiFi Client Roamed | Network |
| 403 | Wired Client Connected | Network |
| 404 | Wired Client Disconnected | Network |
| 510 | Device Updated | Network |
| 544 | Admin Accessed / Network Accessed | Network |
| 545 | Config Created | Network |
| 549 | Config Removed | Network |
| 563 | Poor AP Link Speed | Network |
| 578 | Network Updated (software) | Network |
| 1000 | Admin Accessed UniFi OS | OS |
| 1100 | Application Update Available | OS |
| 1102 | Application Updated | OS |
| 2008 | Access | Protect |
| 2108 | Update | Protect |
| 2150 | Device Disconnected | Protect |
| 2159 | Motion (camera) | Protect |
| 2161 | Smart Detect Zone / Tamper / Loiter | Protect |
| 2201 | Sensor Motion | Protect |
| 2202 | Sensor Opened | Protect |
| 2203 | Sensor Closed | Protect |
| 2308 | Admin Activity | Protect |

Contributions welcome if you discover additional event IDs!

## Testing

Use `wazuh-logtest` to validate decoders and rules:
```bash
# MikroTik DROP
echo 'Feb 25 10:30:00 MikroTik DROP : IPv4 FORWARD IN:ether1 OUT:bridge1 SRC:203.0.113.1 DST:192.168.1.100 PROTO:TCP SPT:12345 DPT:443 (ACK PSH)' | /var/ossec/bin/wazuh-logtest

# UniFi WiFi Connected
echo 'Feb 25 11:04:19 UDM-Pro-Max-AC CEF:0|Ubiquiti|UniFi Network|10.1.85|400|WiFi Client Connected|1|UNIFIcategory=Client Devices UNIFIconnectedToDeviceName=AP-Bureau UNIFIclientAlias=iPhone UNIFIclientIp=192.168.1.100 UNIFIclientMac=aa:bb:cc:dd:ee:01 UNIFIwifiName=MySSID UNIFIwifiBand=6e UNIFIWiFiRssi=-45 UNIFInetworkName=LAN' | /var/ossec/bin/wazuh-logtest

# UniFi OS Admin Accessed
echo 'Mar 13 16:00:00 UDM-Pro-Max-AC CEF:0|Ubiquiti|UniFi OS|5.0.16|1000|Admin Accessed UniFi OS|1|UNIFIhost=Host UNIFIadmin=Admin msg=Admin accessed the UniFi OS' | /var/ossec/bin/wazuh-logtest

# UniFi Config Created (audit)
echo 'Mar 13 10:31:17 UDM-Pro-Max-AC CEF:0|Ubiquiti|UniFi Network|10.2.93|545|Config Created|5|UNIFIcategory=Audit msg=Network Application Update created RADIUS Profile' | /var/ossec/bin/wazuh-logtest

# FortiGate mDNS (should be suppressed - level 0)
echo 'date=2026-02-25 time=13:00:00 devname="fortigate" devid="FGT123" logid="0001000014" type="traffic" subtype="local" level="notice" srcip=fe80::1 dstip=ff02::fb action="deny" service="udp/5353"' | /var/ossec/bin/wazuh-logtest
```

## Tested environment

- Wazuh 4.14.3 (3-VM cluster: server, dashboard, indexer on Ubuntu 25.10)
- MikroTik CCR2004-1G-12S+2XS running RouterOS 7.22rc4
- Ubiquiti UDM Pro Max (firmware 5.0.16) running UniFi Network 10.2.93 and UniFi Protect 7.0.85
- Fortinet FortiGate 60E running FortiOS 7.x
- Proxmox VE
- Syslog transport: UDP/514 via rsyslog

## Roadmap

- [ ] JAMF Protect & Security Cloud integration
- [ ] Fortinet VPN tunnel state monitoring (up/down)
- [ ] UniFi threat/IDS event decoding
- [ ] UniFi Config Modified audit events (not yet seen in CEF syslog)
- [ ] UniFi AP direct logs (hostapd, kernel wlan events from access points)
- [ ] Dashboard templates for OpenSearch/Kibana

## Contributing

PRs welcome! If you have decoders/rules for other devices, feel free to contribute.

## License

MIT License — Use freely, attribution appreciated.

## Credits

Built by [Astier Consulting](https://www.astier-consulting.fr) with assistance from Claude (Anthropic).
