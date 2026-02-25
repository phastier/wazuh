# Wazuh Decoders & Rules for Ubiquiti UniFi and MikroTik RouterOS

Custom Wazuh SIEM integration for **Ubiquiti UniFi (UDM Pro Max)** and **MikroTik RouterOS 7.x** devices, providing comprehensive log decoding, field extraction, and alerting rules.

Developed and tested on **Wazuh 4.14.3** by [Astier Consulting](https://www.astier-consulting.fr) — Apple/IT consulting with 30 years of datacenter management experience.

## Why this project?

When we set out to integrate our UniFi and MikroTik infrastructure into Wazuh, we found that:

- The **BNC community rules** for UniFi (`0999-bnc-unifi-rules.xml`) are outdated and reference decoder names that no longer exist
- There were **no working decoders** for MikroTik RouterOS 7.x with BSD syslog format
- UniFi CEF events (WiFi client tracking, admin access) were **not decoded at all**
- Documentation on Wazuh PCRE2 limitations was scattered and incomplete

This repository provides production-tested decoders and rules that actually work.

## Features

### MikroTik RouterOS 7.x
- **Firewall**: DROP IPv4/IPv6, invalid forward, INPUT protection
- **DHCP**: Server operations (discover, offer, request, ack, lease, removal)
- **Authentication**: Login/logout with external IP detection
- **Correlation rules**: Port scan detection, brute force alerts
- **MITRE ATT&CK**: T1078 (Valid Accounts), T1133 (External Remote Services), T1110 (Brute Force)

### Ubiquiti UniFi (UDM Pro Max)
- **Firewall**: iptables rules with full field extraction (src/dst IP, MAC, ports, flags)
- **WiFi tracking**: Client connected/disconnected/roamed with enriched fields (device alias, AP name, SSID, band, RSSI, duration)
- **Protect**: Smart detection (person/vehicle/animal), motion events, intrusion correlation
- **DHCP**: Pool exhaustion alerts, lease tracking
- **Admin access**: Management interface access with MITRE mapping
- **Noise suppression**: ubios-udapi-server, DPI stats, system events filtered at level 0

## Architecture
```
MikroTik CCR2004 ──┐
                    ├──► Syslog UDP/514 ──► Wazuh Server (rsyslog → analysisd)
UniFi UDM Pro Max ──┘
```

Both devices send BSD syslog format. Wazuh's pre-decoder extracts timestamp and hostname before our custom decoders process the message payload.

## Key technical learnings

These are hard-won lessons from building these integrations:

1. **Wazuh PCRE2: one child decoder per parent** — When multiple `<decoder>` children with `type="pcre2"` share the same `<parent>`, only the first one matches. Solution: create separate parent/child pairs for each log type.

2. **`[^\]]+` fails in Wazuh PCRE2** — Use explicit character classes like `[a-f0-9:]+` for IPv6 addresses instead.

3. **BSD syslog pre-decoder consumes the hostname** — Your decoder `<prematch>` must NOT include the device hostname (e.g., `MikroTik`), as it's already extracted by the pre-decoder.

4. **UniFi CEF `program_name` extraction** — When UDM hostname contains hyphens (`UDM-Pro-Max-AC`), the pre-decoder extracts `program_name: CEF`. Decoders must use `<program_name>^CEF</program_name>` to match.

5. **`<match>` vs `<field>` in rules** — `action` is a static decoded field. Use `<match>` to search the raw log, or `<decoded_as>` with specific decoder names for targeting.

6. **Rule hierarchy matters** — Use `<if_sid>` for child rules. Without it, catch-all rules at the same level may match before specific ones.

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
```

### 3. Set permissions
```bash
chown wazuh:wazuh /var/ossec/etc/decoders/mikrotik_custom.xml
chown wazuh:wazuh /var/ossec/etc/decoders/ubiquiti.xml
chown wazuh:wazuh /var/ossec/etc/rules/mikrotik_rules.xml
chown wazuh:wazuh /var/ossec/etc/rules/unifi_rules.xml
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
| 100310-100315 | UniFi | Protect (smart detect, motion, intrusion) |
| 100320-100321 | UniFi | DHCP (events, pool exhaustion) |
| 100330-100331 | UniFi | Noise suppression (services, DPI) |
| 100340-100344 | UniFi | WiFi & Network CEF (connect, disconnect, roam, admin) |
| 100350 | UniFi | System suppression |

## Decoded fields

### MikroTik WiFi/Firewall
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

## Testing

Use `wazuh-logtest` to validate decoders and rules:
```bash
echo 'Feb 25 10:30:00 MikroTik DROP : IPv4 FORWARD IN:ether1 OUT:bridge1 SRC:203.0.113.1 DST:192.168.0.100 PROTO:TCP SPT:12345 DPT:443 (ACK PSH)' | /var/ossec/bin/wazuh-logtest
```

## Tested environment

- Wazuh 4.14.3 (3-VM cluster: server, dashboard, indexer)
- MikroTik CCR2004-1G-12S+2XS running RouterOS 7.x
- Ubiquiti UDM Pro Max running UniFi Network 10.1.85
- Ubuntu 24.04 / Proxmox
- Syslog transport: UDP/514 via rsyslog

## Contributing

PRs welcome! If you have decoders/rules for other devices (Fortinet, JAMF, etc.), feel free to contribute.

## License

MIT License — Use freely, attribution appreciated.

## Credits

Built by [Astier Consulting](https://www.astier-consulting.fr) with assistance from Claude (Anthropic).
