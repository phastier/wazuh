# Wazuh Custom Decoders & Rules for Network Infrastructure & MDM

Custom Wazuh SIEM integration for **Ubiquiti UniFi (UDM Pro Max)**, **MikroTik RouterOS 7.x**, **Fortinet FortiGate**, and **Jamf Pro (on-prem MDM)**, providing comprehensive log decoding, field extraction, noise suppression, and alerting rules.

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
- **Protect**: Smart detection (person/vehicle/animal/license plate), **smart audio detection** (alarms/glass-break), camera motion, sensor motion, **camera tamper**, loiter, device connect/disconnect, door sensor open/close, admin activity, intrusion correlation
- **IoT sensors**: Door opened/closed events from Protect sensors (category=iot), motion detection from Protect-managed IoT devices
- **OS**: Console access, application update notifications and tracking — covers the UniFi OS layer independently from Network and Protect
- **Audit trail**: Configuration changes (created/modified/removed), software updates, console access — essential for DORA/compliance
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

### Jamf Pro (on-prem MDM)
Custom decoders and rules for Jamf Pro's application logs — no community Wazuh decoders exist for these file-based logs. Jamf Pro does **not** write to syslog; logs are collected from the host with the Wazuh agent.

- **Authentication** (`JSSAccess.log`): console & API logins (success/failure), logout, API token creation, password changes — with user, source IP and entry point (JSS console / Universal API / OAuth)
- **Audit trail** (`JAMFChangeManagement.log`): full CRUD on every Jamf object (accounts, groups, policies, configuration profiles, scripts, MDM commands, settings…) with actor, action and object type
- **Full audit visibility**: every event is decoded and surfaced — including READ access at a low level (3) with the object name extracted — so nothing is hidden by default; sensitive-object reads (level 5) and FileVault key access (level 12) are escalated. Reads are ~96% of the audit volume, so set rule `100511` to level 0 to suppress them once you have decided what you do not want to see.
- **Sensitive object escalation**: admin **Account** changes (level 10), **API client / client secret** changes (level 12), **MDM commands** (level 9) with **destructive commands** (erase / wipe / unmanage) at level 12, **security settings** (Jamf Protect, Conditional Access, Change Management, Push Certificate, SMTP) (level 8)
- **FileVault recovery key (PRK) access** (level 12): detects an admin viewing a computer's FileVault Personal Recovery Key — Jamf logs this as an empty-object `READ` whose body carries `File Vault 2 ID` (requires multi-line collection)
- **Object name extraction** (`jamf_object_name`): pulls the changed object's name from the multi-line body (e.g. which script/policy/profile)
- **Brute force correlation**: repeated failed logins from the same source IP
- **Instance install/upgrade tracking** (`jamf-pro-installer.log`): Jamf Pro upgrades, upgrade steps, disk-space warnings (level 5) and install failures (level 10) — the noisy `JAMFSoftwareServer.log` is intentionally *not* collected (99% INFO + a single recurring internal ERROR)
- **MITRE ATT&CK**: T1110 (Brute Force), T1098 (Account Manipulation), T1555 (Credentials from Password Stores), T1562.001 / T1070 (Impair Defenses / Indicator Removal)

## Architecture
```
MikroTik CCR2004 ──────┐
                        │
UniFi UDM Pro Max ──────┼──► Syslog UDP/514 ──► Wazuh Server (rsyslog → analysisd)
                        │
Fortinet FortiGate ─────┘
```

MikroTik and UniFi send BSD syslog format. FortiGate uses its native key=value syslog format. Wazuh's pre-decoder extracts timestamp and hostname before custom decoders process the message payload.

**Jamf Pro is collected differently**: it does not emit syslog, so its `JSSAccess.log` and `JAMFChangeManagement.log` (and `jamf-pro-installer.log`) are read directly on the Jamf Pro host by the Wazuh agent via `<localfile>` — there is no syslog pre-decoder, so the decoders match the raw file lines. See [Device configuration](#jamf-pro-on-prem).

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

13. **UniFi debug mode reveals hidden CEF events** — Some CEF event types (like Config Modified, ID 546) only appear when syslog is set to debug level. Enable debug temporarily to discover all available event types, then revert to normal.

14. **UniFi Protect needs its own CEF parent decoder** — A hyphenated UDM hostname makes the BSD pre-decoder set `program_name=CEF` (learning #4); once that happens, the bare `ubiquiti` prematch decoder no longer matches, so **Protect events silently stop decoding** (`decoder: {}`, no alert) while Network/OS keep working because they have dedicated `*-cef-parent` decoders with `<program_name>^CEF</program_name>`. Fix: add a `unifi-protect-cef-parent` (program_name CEF + prematch `Ubiquiti\|UniFi Protect`) and point the Protect rule (100312) at it instead of `decoded_as ubiquiti`. Symptom to watch for: UniFi *Network* events alert but *Protect* events (smart detect, tamper, motion) never do.

15. **UniFi AP (hostapd) events collide with the built-in `symantec-av` decoder** — Access points/switches send syslog as `<12-hex-MAC>,<model>: hostapd[..]: ... STA <mac> IEEE 802.11: associated|disassociated`. That leading `<12 hex>,` matches the built-in `symantec-av` prematch (`^\w{12},`); its own regex then fails (our prefix is hex, not the digits-CSV it expects). On some Wazuh builds the engine falls through to the next decoder so `unifi-ap` matches, but on others (observed on 4.14.5) it **locks onto `symantec-av` on the prematch alone** — AP client connect/disconnect events get mis-labelled "symantec-av" (fires rule 7300) and `unifi-ap` never runs. **Two managers on the same version can behave differently here** (decoder_dir ordering does NOT override it). Fix — upgrade-safe, no base-file edits — exclude the symantec decoder in `ossec.conf`: `<decoder_exclude>0330-symantec_decoders.xml</decoder_exclude>` plus the matching `<rule_exclude>` lines. Symptom to watch for: "who connects to which AP/switch" events appear under Symantec AV instead of UniFi.

## Installation

### 1. Copy decoders
```bash
cp decoders/mikrotik_custom.xml /var/ossec/etc/decoders/
cp decoders/ubiquiti.xml /var/ossec/etc/decoders/
cp decoders/unifi_ap.xml /var/ossec/etc/decoders/      # UniFi AP hostapd (client assoc/disassoc) - see learning #15
# Only if you use UniFi Protect (CEF format):
cp decoders/unifi.xml /var/ossec/etc/decoders/
```

### 2. Copy rules
```bash
cp rules/mikrotik_rules.xml /var/ossec/etc/rules/
cp rules/unifi_rules.xml /var/ossec/etc/rules/
cp rules/unifi_ap_rules.xml /var/ossec/etc/rules/      # UniFi AP hostapd rules (100368-100370)
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

### 4. Disable conflicting built-in decoders/rules
Add to `/var/ossec/etc/ossec.conf` inside `<ruleset>`:
```xml
<rule_exclude>0999-bnc-unifi-rules.xml</rule_exclude>
<!-- Required for UniFi AP hostapd events (see learning #15): the built-in
     symantec-av decoder false-matches the "<12-hex>," AP syslog prefix. -->
<decoder_exclude>0330-symantec_decoders.xml</decoder_exclude>
<rule_exclude>0120-symantec-av_rules.xml</rule_exclude>
<rule_exclude>0125-symantec-ws_rules.xml</rule_exclude>
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

### Jamf Pro (on-prem)
Jamf Pro writes log4j files under `/usr/local/jss/logs/` — it does **not** send syslog. Install the Wazuh agent on the Jamf Pro host and add to `/var/ossec/etc/ossec.conf`:
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/usr/local/jss/logs/JSSAccess.log</location>
</localfile>
<localfile>
  <log_format>multi-line-regex</log_format>
  <location>/usr/local/jss/logs/JAMFChangeManagement.log</location>
  <multiline_regex match="start" replace="no-replace">^\[</multiline_regex>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/usr/local/jss/logs/jamf-pro-installer.log</location>
</localfile>
```
`JAMFChangeManagement.log` is collected as **multi-line** (`match="start"` on the `^[` header) so each change is a single event carrying the header **plus** the detail body — i.e. the object name and the changed fields, not just the object type. Note that Jamf logs mostly metadata, but some changes (Configuration Profile payloads, script-content edits) include larger/sensitive blobs — tune at the agent or rule level if needed. Then restart the agent. In Jamf Pro, enable the audit trail under **Settings → System → Change Management → Use Log File** (directory `/usr/local/jss/logs`). The agent runs as root, so it can read both files regardless of their `jamftomcat` ownership.

> **Why file collection and not syslog?** Jamf Pro's Change Management can alternatively forward to a syslog server (*Settings → System → Change Management → Use Syslog Server*). We deliberately **chose not to** (for now): syslog only covers Change Management — not `JSSAccess.log` or the installer log — it can drop events over UDP, and being line-oriented it would lose the multi-line detail body that carries the **object name** and the FileVault recovery-key signature (`File Vault 2 ID`). File collection via the agent keeps everything, reliably. (Use syslog instead if you only need a condensed change feed forwarded to a central collector.)

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
| 100310-100316 | UniFi | Protect (smart detect, camera/sensor motion, door sensor, admin activity, intrusion correlation) |
| 100320-100321 | UniFi | DHCP (events, pool exhaustion) |
| 100330-100331 | UniFi | Noise suppression (services, DPI) |
| 100340-100349 | UniFi | WiFi, Wired, Network CEF, Device Updates, UPS power |
| 100350 | UniFi | System suppression |
| 100351-100357 | UniFi | Network audit & infra (admin console access w/ IP, config created/modified incl. security-setting escalation, removed, software updates, AP link speed) |
| 100358-100359 | UniFi | IDS/IPS threat detected & blocked (readable signature + src/dst; high-risk escalated to L10) |
| 100360-100363 | UniFi | OS events (console access, application update available/completed) |
| 100364-100367 | UniFi | Protect (camera tamper, smart audio detect, device connect/disconnect) |
| 100368-100372 | UniFi | AP per-AP syslog (readable daemon+message, Wi-Fi client assoc/disassoc, fan/thermal telemetry + high-temp escalation) |
| 100380 | UniFi | Switch per-switch syslog (readable daemon+message) |
| 100381-100382 | UniFi | AP mesh topology (meshed / lost mesh uplink) |
| 100383-100384 | UniFi | IDS/IPS outbound threat (internal client reached a flagged destination; high-risk escalated) |
| 100400-100401 | FortiGate | Noise suppression (mDNS, UniFi discovery) |
| 100410-100411 | FortiGate | VPN IPsec (denied traffic, VPN events) |
| 100420-100422 | FortiGate | System (perf stats, disk rotation, AV updates) |
| 100430 | FortiGate | Correlation (repeated VPN denies) |
| 100500-100507 | Jamf Pro | Authentication (login, logout, token, failed login, password change, brute force) |
| 100510-100516 | Jamf Pro | Change management (READ surfaced at low level + object name, sensitive objects + FileVault PRK escalated, create/update/delete) |
| 100520-100525 | Jamf Pro | Sensitive object changes (API client/secret, account, MDM commands incl. destructive erase/wipe, security settings, audit log retention) |
| 100530-100534 | Jamf Pro | Instance install/upgrade (upgrade steps, disk warning, install failure) |

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

### UniFi AP — per-AP syslog
| Field | Content | Example |
|-------|---------|---------|
| `ap_daemon` | Daemon that emitted the line | `syswrapper` / `wpa_supplicant` |
| `ap_message` | Readable message body | `Trigger rrm scan(1): ...` |
| `client_mac` | Wi-Fi client MAC (assoc/disassoc) | `aa:bb:cc:dd:ee:01` |
| `ap_radio` | Radio interface | `wifi1ap2` |
| `wifi_action` | Association state | `associated` / `disassociated` |
| `ap_model` | AP model + firmware | `U6-IW-6.8.2+15592` |

### UniFi AP — fan/thermal telemetry
| Field | Content | Example |
|-------|---------|---------|
| `ap_temp` | Sensor temperature (°C) | `76` |
| `sensor_zone` | Sensor zone | `zone3` |
| `fan_speed` | Fan speed (%) | `0` |
| `fan_rpm` | Fan RPM | `0` |
| `pwm_set` / `pwm_actual` | Fan PWM set / actual | `63` / `55` |

### UniFi Wired client (enriched)
| Field | Content | Example |
|-------|---------|---------|
| `dstuser` | Client alias | `Living-Room-TV` |
| `srcip` | Client IP | `192.168.20.37` |
| `srcmac` | Client MAC | `aa:bb:cc:dd:ee:02` |
| `switch_name` | Switch/AP it connected to | `USW-Flex-Office` |
| `switch_port` | Port number | `2` |
| `network` / `vlan` | Network name / VLAN id | `VLAN_IoT` / `200` |
| `data` | Session duration (on disconnect) | `1h 52m` |

### UniFi Switch — per-switch syslog
| Field | Content | Example |
|-------|---------|---------|
| `sw_daemon` | Daemon that emitted the line | `mcad` |
| `sw_message` | Readable message body | `ui-ubus-utils...: Failed to find ubus object` |
| `sw_model` | Switch model + firmware | `USW-Pro-Max-48-7.5.4+17029` |

### UniFi IDS/IPS threat (Threat Detected and Blocked)
| Field | Content | Example |
|-------|---------|---------|
| `signature` | IPS signature / threat name | `ET MALWARE ... RAT C2 Domain in DNS Lookup` |
| `risk` | Risk level | `high` |
| `policy` | Policy name | `Malware and Trojans` |
| `srcip` / `dstip` | Source / destination IP | `192.0.2.10` / `198.51.100.5` |
| `signature_id` | IPS signature ID | `2068515` |
| `srcuser` / `srcmac` | Internal client (outbound threat) | `LAPTOP-1` / `aa:bb:cc:dd:ee:ff` |

### UniFi admin / audit (console access, config change)
| Field | Content | Example |
|-------|---------|---------|
| `dstuser` | Admin who performed the action | `jdoe` |
| `srcip` | Source IP of the admin | `203.0.113.10` |
| `access_method` | Access method (console access) | `web` |
| `setting` | Setting key changed (config modified) | `ip_filtering.countries` |

### UniFi AP mesh (AP Meshed / Stopped Mesh)
| Field | Content | Example |
|-------|---------|---------|
| `ap_name` | AP whose mesh state changed | `AP-Garden` |
| `mesh_parent` | Mesh uplink AP (new or prior) | `AP-House` |

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

| ID | Event | Source | Note |
|----|-------|--------|------|
| 215 | UPS Battery Power In Use | Network | |
| 216 | UPS AC Power Restored | Network | |
| 400 | WiFi Client Connected | Network | |
| 401 | WiFi Client Disconnected | Network | |
| 402 | WiFi Client Roamed | Network | |
| 403 | Wired Client Connected | Network | |
| 404 | Wired Client Disconnected | Network | |
| 510 | Device Updated | Network | |
| 544 | Admin Accessed / Network Accessed | Network | |
| 545 | Config Created | Network | |
| 546 | Config Modified | Network | Requires debug syslog level |
| 549 | Config Removed | Network | |
| 563 | Poor AP Link Speed | Network | |
| 578 | Network Updated (software) | Network | |
| 1000 | Admin Accessed UniFi OS | OS | |
| 1100 | Application Update Available | OS | |
| 1102 | Application Updated | OS | |
| 2008 | Access | Protect | |
| 2103 | Device Connected | Protect | |
| 2108 | Update | Protect | |
| 2150 | Device Disconnected | Protect | |
| 2159 | Motion (camera) | Protect | |
| 2161 | Smart Detect: Zone / Loiter / Tamper / Audio | Protect | Tamper & audio have dedicated rules |
| 2201 | Sensor Motion | Protect | Also appears with category=iot |
| 2202 | Sensor Opened | Protect | Also appears with category=iot |
| 2203 | Sensor Closed | Protect | |
| 2308 | Admin Activity | Protect | |

> **Note**: Some Protect sensor events (2201, 2202) can appear with `UNIFIcategory=iot` instead of `UNIFIcategory=detection`. Both are handled by the same rules.

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

# UniFi Config Modified (audit)
echo 'Mar 14 08:16:22 UDM-Pro-Max-AC CEF:0|Ubiquiti|UniFi Network|10.2.93|546|Config Modified|5|src=192.168.0.39 UNIFIcategory=Audit UNIFIsettingsChanges=debug: true UNIFIsettingsSection=System UNIFIadmin=Admin msg=Admin made a change in System settings' | /var/ossec/bin/wazuh-logtest

# FortiGate mDNS (should be suppressed - level 0)
echo 'date=2026-02-25 time=13:00:00 devname="fortigate" devid="FGT123" logid="0001000014" type="traffic" subtype="local" level="notice" srcip=fe80::1 dstip=ff02::fb action="deny" service="udp/5353"' | /var/ossec/bin/wazuh-logtest

# Jamf Pro: failed login (level 8)
echo '2026-06-29 08:28:01,037: username=jdoe, status=Failed Login, ipAddress=192.0.2.10, entryPoint=JSS' | /var/ossec/bin/wazuh-logtest

# Jamf Pro: admin account created (level 10)
echo '[jdoe (ID: 5)] [CREATE] [Account] [2026-06-29T10:02:00.791+0200]' | /var/ossec/bin/wazuh-logtest

# Jamf Pro: API client secret deleted (level 12, critical)
echo '[jdoe (ID: 5)] [DELETE] [API Client - Client Secret] [2026-06-29T10:02:00.772+0200]' | /var/ossec/bin/wazuh-logtest
```

## Tested environment

- Wazuh 4.14.5 (3-VM cluster: server, dashboard, indexer)
- MikroTik CCR2004-1G-12S+2XS running RouterOS 7.x
- Ubiquiti UDM Pro Max / UDM SE running UniFi Network 10.4–10.5 and UniFi Protect 7.x — plus access points (U6-IW, U7-Pro, UDB) and switches (USW-Pro-Max-48, USW-Flex 2.5G) on firmware 6.x–8.x
- Fortinet FortiGate 60E running FortiOS 7.x
- Proxmox VE
- Syslog transport: UDP/514 via rsyslog

> Versions move fast; these decoders are kept working across newer Wazuh, RouterOS and UniFi releases, so the exact versions above are a snapshot, not a hard requirement.

## Roadmap

- [ ] JAMF Protect & Security Cloud integration
- [ ] Fortinet VPN tunnel state monitoring (up/down)
- [ ] UniFi threat/IDS event decoding
- [x] UniFi AP direct logs — readable per-AP syslog (daemon+message), Wi-Fi client assoc/disassoc, fan/thermal telemetry (`unifi_ap.xml`, rules 100368-100372); needs symantec `decoder_exclude` (learning #15)
- [x] UniFi switch direct logs — readable per-switch syslog (`unifi_switch.xml`, rule 100380; exclude BNC decoders if present)
- [ ] Dashboard templates for OpenSearch/Kibana

## Contributing

PRs welcome! If you have decoders/rules for other devices, feel free to contribute.

## License

MIT License — Use freely, attribution appreciated.

## Credits

Built by [Astier Consulting](https://www.astier-consulting.fr) with assistance from Claude (Anthropic).
