# Wazuh Custom Decoders & Rules for Network Infrastructure & MDM

Custom Wazuh SIEM integration for **Ubiquiti UniFi (Network controller — UDM Pro Max, UDM SE or any UniFi OS console — plus APs, switches, UPS)**, **MikroTik RouterOS 7.x**, **Fortinet FortiGate**, **Stormshield SNS (SN-series NG firewalls)**, **Jamf Pro (on-prem MDM)**, and **Linux/Proxmox hosts (journald)**, providing comprehensive log decoding, field extraction, noise suppression, and alerting rules.

It also ships an **in-situ log anonymiser** (`tools/sns-anonymize.py`) so you can build and share decoder sample corpora without ever exposing production personal data — see [Log anonymiser](#log-anonymiser).

The design philosophy is **decode everything, then triage by level**: every event type a device can emit gets decoded and traced (level 1 = archived without alerting), and only meaningful events alert (level 3+). Nothing is silently dropped — noise reduction happens at the source or at the rule level, never by leaving events undecoded.

Developed and tested on **Wazuh 4.14.3** by [Astier Consulting](https://www.astier-consulting.fr) — Apple/IT consulting with 30 years of datacenter management experience.

## Why this project?

When we set out to integrate our network infrastructure into Wazuh, we found that:

- The **BNC community rules** for UniFi (`0999-bnc-unifi-rules.xml`) are outdated and reference decoder names that no longer exist
- There were **no working decoders** for MikroTik RouterOS 7.x with BSD syslog format
- UniFi CEF events (WiFi client tracking, admin access) were **not decoded at all**
- Fortinet built-in decoders work well, but **without tuning, mDNS/Bonjour noise drowns out real alerts** — especially in Apple-heavy environments
- **Stormshield SNS** firewalls emit a rich `key="value"` syslog — traffic decisions, IPS alarms, IPsec/SSL VPN, admin audit, DHCP — that **no community Wazuh decoder** handles, so every event landed undecoded
- Documentation on Wazuh PCRE2 limitations was scattered and incomplete

This repository provides production-tested decoders and rules that actually work, along with noise suppression tuning for real-world mixed environments.

## Features

### MikroTik RouterOS 7.x
Custom decoders and rules — nothing usable existed for RouterOS 7.x BSD syslog.

- **Firewall**: DROP IPv4/IPv6, invalid forward, INPUT protection
- **DHCP**: Server operations (discover, offer, request, ack, lease, removal)
- **DHCP bindings**: `assigned`/`deassigned` with IP↔MAC↔hostname extraction (live inventory), `offering lease ... without success` (client not completing)
- **DHCP debug option dump**: one-option-per-line debug output decoded with a whitelisted option list (`mikrotik_dhcp_extra.xml`)
- **Interface links**: SFP+/ether link up/down with speed and duplex, plus a **flapping correlation rule** (6+ transitions in 5 min → level 8)
- **Authentication**: Login/logout with external IP detection
- **Correlation rules**: Port scan detection, brute force alerts
- **MITRE ATT&CK**: T1078 (Valid Accounts), T1133 (External Remote Services), T1110 (Brute Force)

### Ubiquiti UniFi (Network controller)
Custom decoders and rules — the existing BNC community rules are broken. The CEF/syslog these parse is emitted by the **UniFi Network controller** itself, not by a specific box, so this applies to any UniFi OS console — **validated on UDM Pro Max and UDM SE**, and should hold on UDR, Cloud Key, UXG and self-hosted controllers running comparable Network/Protect versions.

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
- **UDM system syslog in debug mode** (`unifi_udm_syslog.xml`): in debug mode the UDM *doubles its hostname* in every system line, which silently breaks `program_name` pre-decoding — sudo, systemd, earlyoom, `ips-update.sh` all go undecoded. Dedicated decoders restore: **sudo audit trail** (who ran what as root), **IPS list update failures** (`tor.list.gz`, `alien.list.gz` checksum errors — level 5, repeated failures level 10), **memory pressure** (earlyoom telemetry with a <10% level-8 alert), systemd unit failures
- **AP kernel events** (`unifi_ap_kernel.xml`): `kernel:` lines carry no PID and escape the hostapd decoders. Covers **802.11 auth/assoc frames** (station MAC, RSSI, algorithm — real security value), per-client **DHCP state machine** traces, **DNS timeout tracking** per station, **VLAN assignment failures**, and generic wlan errors/warnings
- **USW-Flex 2.5G & UPS Tower** (`unifi_mca.xml`): these adopt-managed devices log **without a syslog timestamp** (the line starts with the hostname), so the pre-decoder extracts nothing and every event was undecoded. Covers MCA informs, **controller inform failures** (HTTP 4xx/5xx with a persistent-failure correlation → level 7), port link up/down, STP transitions

### Fortinet FortiGate
Supplementary rules on top of Wazuh's built-in FortiGate decoders (which work well). The focus here is **noise suppression and VPN monitoring** — in environments with Apple devices, Bonjour/mDNS generates thousands of deny logs per minute that bury real security events.

- **mDNS/LLMNR suppression**: Filters out the massive volume of UDP/5353 and UDP/5355 deny logs typical in Apple/HomeKit/Bonjour environments
- **UniFi discovery suppression**: Filters UDP/10001 broadcast noise
- **VPN IPsec monitoring**: Alerts on denied traffic through site-to-site tunnels (routing issues, unauthorized access attempts). Filters on `action="deny"` to avoid false positives from legitimate ZTNA traffic
- **System events**: Performance stats, AV database updates, disk log rotation
- **Correlation**: Repeated VPN denies trigger higher-level alerts for investigation

### Stormshield SNS (SN-series NG firewall)
Custom decoders and rules for **Stormshield Network Security** appliances — no community Wazuh decoders exist for the SNS `key="value"` syslog format. Every event begins with `id=firewall ... logtype="<type>"`; one parent decoder on the `id=firewall ` signature dispatches to a child per logtype, with a catch-all so unknown logtypes still decode (`stormshield_sns.xml`).

- **Traffic** (`filter` / `connection`): allowed/denied decisions with the 5-tuple (src/dst IP, ports, protocol), source user (SSL-VPN), interfaces. Allowed traffic is telemetry (level 1); blocks alert (level 3)
- **SSL/TLS inspection** (`ssl`): decipher verdict + message (e.g. *"Connection not deciphered"*, *"OpenVPN connection detected"*) — blocked SSL raised to level 4
- **IPS / protections** (`alarm`): alarm id, class, target and risk — level 6, **high-risk (risk ≥ 7) escalated to level 10**
- **Authentication** (`auth`): events such as *"deprecated hash method"* (weak password hashing) — level 5
- **SSL VPN** (`xvpn`): nominative remote-access sessions (tunnel created, user authenticated) — level 4
- **IPsec VPN** (`vpn`): IKE tunnel events (SA established/deleted), negotiation failures escalated to level 8
- **Firewall admin audit** (`server`): who administers the appliance (webadmin login + serverd CLI/config commands) — level 5, **configuration changes raised to level 8**
- **DHCP** (`system`, `service=dhcp`): **`DHCPACK` = who is connected** — IP/MAC/hostname extracted into `dhcp.*` fields for an asset inventory (level 3); other DHCP verbs stay telemetry
- **Periodic statistics** (`ipsecstat` / `filterstat` / `authstat`): IKE SA count, accepted/blocked totals, auth counters — traced at level 1
- **Field mapping**: 5-tuple to Wazuh static fields; the firewall verdict is a *dynamic* field `fw.action` (the static `action` field is rejected in rule matching on some builds — learning #23)

### Linux / Proxmox hosts (journald)
Decoders and rules for common programs collected by Wazuh agents through journald and left undecoded by the stock ruleset (`journald_extra.xml`):

- **ZFS zed**: `eid/class/pool` extraction — **io/data/checksum errors at level 9**, error burst (10+ in 1 min on the same pool) at level 12, scrubs informational. Catches real incidents: ENOSPC/ENXIO bursts show up here before anything else complains
- **Proxmox pvescheduler**: backup job start/finish per VM (level 3), backup errors (level 8)
- **Debian/Ubuntu CRON via journald**: the journald `program_name` is `CRON`, which the stock `crond` decoder does not match — decoded with user + command extraction
- **qemu-ga**: guest fsfreeze/fsthaw calls during backups
- **LibreNMS service**: component/level/message extraction — polling INFO reclassified to level 1, ERROR/CRITICAL/WARNING at level 5
- Program-only decoders for chronyd, snapd, dbus-daemon, pmxcfs, corosync, canonical-livepatch, fwupd, smokeping, opensearch-dashboards, proxmox-backup-proxy, and more — every journald event ends up decoded and traceable

### Web access log — scanner detection
Malformed nginx/Apache access-log entries that the stock `web-accesslog` decoder ignores (`web_accesslog_malformed.xml`): empty requests (`"" 400`) and binary payloads (TLS handshakes sent to a plaintext port). These are exactly what Internet scanners generate against public endpoints. Each probe alerts at level 5 with `srcip` extracted; 6+ probes from the same source in 5 minutes escalate to level 8.

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

### Authentik IdP (goauthentik)
Decoders and rules for authentik's structlog JSON, collected through the Docker **journald logging driver** — no syslog listener, no sidecar, no log files to rotate. The audit trail (`logger=authentik.events.models`) is the compliance signal; HTTP access and worker chatter stay decoded at level 0, searchable in the archives.

- **Audit trail**: login / logout with user, client IP and auth method; **failed login (level 5) with brute-force correlation** (6+ failures from the same IP in 2 min → level 10); application authorization; account/credential changes (`user_write`, `password_set`, `password_reset`); admin object changes (providers, flows, policies, applications); **impersonation** and `suspicious_request` (level 8); policy/configuration exceptions
- **HTTP access** (`authentik.asgi`): every request decoded; 401/403 access denied (level 5), 404s with **scanner correlation** (10+ from the same source in 2 min → level 8 — seen live: `GET /.env` sweeps), 5xx server errors
- **Framework security** (`django.security.*`) plus a generic warn/error/critical mapping, so no logger escapes unclassified
- **Compliance tagging** on the audit rules: PCI DSS, GDPR, HIPAA, NIST 800-53, TSC
- **MITRE ATT&CK**: T1078 (Valid Accounts), T1110 / T1110.001 (Brute Force), T1098 (Account Manipulation), T1595 (Active Scanning)

## Architecture
```
MikroTik router (RouterOS) ──┐
UniFi Network controller ────┤
Fortinet FortiGate ──────────┼──► Syslog UDP/514 ──► Wazuh Server (rsyslog → analysisd)
Stormshield SNS ─────────────┘
```

MikroTik and UniFi send **BSD syslog**; FortiGate and Stormshield SNS send their native **`key=value` syslog**. Wazuh's pre-decoder extracts timestamp and hostname before the custom decoders process the message payload. **Jamf Pro, Authentik and Linux/Proxmox hosts are collected by the Wazuh agent** (`<localfile>` / journald), not syslog.

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

16. **A parent decoder's `<regex>`/`<order>` is IGNORED once it has children** — analysisd never applies the parent's own field extraction when `<parent>` children exist, whether a child matches or not. Pattern that works: parent = `<prematch>` only; every child captures all the fields it needs (including "parent-level" identity like program/pid or device MAC); finish with one or two catch-all children that capture identity + message for lines no specific child handles.

17. **A child whose prematch matches but whose regex fails STOPS the sibling chain** — the remaining children are never tried and the event stays field-less. A trailing period is enough to trigger this (`Succeeded.` vs a regex ending in `(Succeeded|Failed.*)$`). Keep child regex endings tolerant: `[^.]*`, `\.?$`.

18. **Root rules are evaluated by descending level — stock rule 1002 steals your events** — a level-1 base rule on `decoded_as` loses every log containing `failed`/`error` to the built-in "Unknown problem" rule 1002 (level 2). Put base `decoded_as` rules at level 3 and reclassify noise down to level 1 through child rules; never anchor a rule tree on a level-1/2 root.

19. **`<field name="status">` is rejected in rules** — `status` (like `action`, `id`, `srcip`...) is a *static* field; analysisd fails to load the rule with "Field 'status' is static". Match static fields with their dedicated element (`<status>^down$</status>`, OS_Match syntax — no `\d` classes) or fall back to `<match>` on the raw log.

20. **`<program_name>` uses OS_Regex where `\d*` does not match** — `^python\d*$` silently matches nothing. Use literal alternations: `^python$|^python2$|^python3$`.

21. **UDM debug syslog doubles the hostname and kills `program_name` pre-decoding** — in debug mode every UDM *system* line reads `UDM-Pro-Max-AC UDM-Pro-Max-AC prog[pid]: msg`; the BSD pre-decoder consumes the first hostname, chokes on the second, and never sets `program_name` — so sudo/systemd/earlyoom events silently stop matching the stock decoders. `unifi_udm_syslog.xml` re-extracts program/pid from the message body (anchored `^UDM-` so it also covers UDM SE).

22. **Some UniFi devices log with NO syslog timestamp** — USW-Flex 2.5G switches and UPS Tower units send `HOSTNAME <mac>,<model>-<fw>: SUBSYS: msg` with no timestamp at all; the pre-decoder extracts nothing and prematches must match from the raw line start (`^\S+ [0-9a-fA-F]{12},...`).

23. **Stormshield SNS `key="value"`: dispatch on the trailing `logtype=`, keep the verdict dynamic** — every SNS event ends with `logtype="filter|ssl|alarm|vpn|server|..."`. One parent on `^id=firewall ` + one child per logtype (each discriminating on its own `logtype=`) + a catch-all last decodes every type cleanly. Decode the firewall verdict into a **dynamic** field (`fw.action`), not the static `action` — matching a static field with `<field name="action">` fails on some builds (learnings #5/#19). Space-bearing values (`msg="..."`) need a quoted capture, and ` src=`/` dst=` must be **space-anchored** so they don't match `modsrc=`/`origdst=`.

24. **Wazuh `<field>` matching is substring, not exact — anchor it** — `<field name="logtype">auth</field>` also matches `authstat` (and `vpn` matches `xvpn`), so the wrong rule fires and the specific one never runs. Anchor every discriminating field match: `<field name="logtype" type="pcre2">^auth$</field>`. Same trap as prematches (learning #7), one layer up in the rules.


## Installation

### 1. Copy decoders
```bash
cp decoders/mikrotik_custom.xml /var/ossec/etc/decoders/
cp decoders/mikrotik_dhcp_extra.xml /var/ossec/etc/decoders/   # DHCP bindings + debug dump + iface links
cp decoders/ubiquiti.xml /var/ossec/etc/decoders/
cp decoders/unifi_ap.xml /var/ossec/etc/decoders/      # UniFi AP hostapd (client assoc/disassoc) - see learning #15
cp decoders/unifi_ap_kernel.xml /var/ossec/etc/decoders/       # UniFi AP kernel: 802.11 auth/assoc, DHCP-SM, DNS timeouts
cp decoders/unifi_udm_syslog.xml /var/ossec/etc/decoders/      # UDM system syslog in debug mode (doubled hostname) - see learning #21
cp decoders/unifi_mca.xml /var/ossec/etc/decoders/             # USW-Flex 2.5G + UPS Tower (no syslog timestamp) - see learning #22
cp decoders/journald_extra.xml /var/ossec/etc/decoders/        # zed, pvescheduler, CRON, qemu-ga, LibreNMS...
cp decoders/web_accesslog_malformed.xml /var/ossec/etc/decoders/  # scanner probes on public endpoints
cp decoders/authentik.xml /var/ossec/etc/decoders/             # Authentik IdP (structlog JSON via journald)
# Only if you have a Stormshield SNS firewall:
cp decoders/stormshield_sns.xml /var/ossec/etc/decoders/          # Stormshield SNS key=value syslog (all logtypes)
# Only if you use UniFi Protect (CEF format):
cp decoders/unifi.xml /var/ossec/etc/decoders/
```

### 2. Copy rules
```bash
cp rules/mikrotik_rules.xml /var/ossec/etc/rules/
cp rules/mikrotik_extra_rules.xml /var/ossec/etc/rules/        # DHCP bindings, link flapping (100800-100806)
cp rules/unifi_rules.xml /var/ossec/etc/rules/
cp rules/unifi_ap_rules.xml /var/ossec/etc/rules/      # UniFi AP hostapd rules (100368-100370)
cp rules/unifi_ap_kernel_rules.xml /var/ossec/etc/rules/       # AP kernel events (100750-100758)
cp rules/unifi_udm_sys_rules.xml /var/ossec/etc/rules/         # UDM system: sudo, IPS updates, earlyoom (100700-100708)
cp rules/unifi_mca_rules.xml /var/ossec/etc/rules/             # USW-Flex + UPS Tower (100770-100778)
cp rules/journald_extra_rules.xml /var/ossec/etc/rules/        # zed, pvescheduler, CRON... (100840-100858)
cp rules/web_malformed_rules.xml /var/ossec/etc/rules/         # scanner detection (100820-100821)
cp rules/stormshield_sns_rules.xml /var/ossec/etc/rules/       # Stormshield SNS (100900-100919)
cp rules/authentik_rules.xml /var/ossec/etc/rules/             # Authentik IdP (101000-101042)
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

### UniFi Network controller (via Network UI)
On the UniFi Network controller (UDM Pro Max/SE, UDR, Cloud Key, UXG, self-hosted…), navigate to **Settings → System → Activity Logging (Syslog)**:
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

### Stormshield SNS
On the appliance, add a syslog profile under **Configuration → Notifications → Logs - Syslog - IPFIX → Syslog**: destination = your Wazuh server, **UDP port 514**, and enable the log families you want (filter, connection, alarm, system, ssl, vpn, xvpn, server, authentication…). Then declare a syslog listener on the Wazuh manager in `/var/ossec/etc/ossec.conf` and restart:
```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>10.0.0.1/32</allowed-ips>   <!-- the SN's real source IP -->
</remote>
```
> **Firewall self-traffic through IPsec**: if the SN reaches Wazuh over a *policy-based* IPsec tunnel, its **self-originated** syslog must be sourced from an IP inside the tunnel's local network, or it never enters the tunnel. Confirm the received source with `sudo tcpdump -ni any udp port 514` on the Wazuh host, then pin `<allowed-ips>` to that exact `/32` — otherwise `wazuh-remoted` silently drops packets whose source isn't whitelisted.

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

### Authentik (Docker → journald)
Authentik containers write structlog JSON to stdout. Route it through the host's journald with the Docker logging driver — the tag becomes the journald `program_name` the decoder matches on:

```yaml
# docker-compose.yml — same block on the worker service with tag authentik-worker
services:
  server:
    logging:
      driver: journald
      options:
        tag: authentik-server
```

Agent side (`/var/ossec/etc/ossec.conf`), the standard journald collection is all it takes:
```xml
<localfile>
  <location>journald</location>
  <log_format>journald</log_format>
</localfile>
```

Recreate the containers (`docker compose up -d`) for the driver change to apply. The decoder carries **no payload regex**: the JSON plugin decoder extracts every key (`logger`, `event`, `action`, `client_ip`, nested `user.username`, `context.*`, `method`, `status`, `remote`), which keeps it robust across authentik releases. Non-JSON payloads (tracebacks) still match the parent decoder, so the severity-mapping rules see them.

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
| 100440-100445 | FortiGate | IPsec tunnel state (tunnel down L8, up L3, phase-2 L5/L3, flapping L10, stats/negotiation traced L1) |
| 100500-100507 | Jamf Pro | Authentication (login, logout, token, failed login, password change, brute force) |
| 100510-100516 | Jamf Pro | Change management (READ surfaced at low level + object name, sensitive objects + FileVault PRK escalated, create/update/delete) |
| 100520-100525 | Jamf Pro | Sensitive object changes (API client/secret, account, MDM commands incl. destructive erase/wipe, security settings, audit log retention) |
| 100530-100534 | Jamf Pro | Instance install/upgrade (upgrade steps, disk warning, install failure) |
| 100700-100708 | UniFi | UDM system syslog (sudo trail, IPS list update failures + repeat escalation L10, earlyoom memory <10% L8, systemd unit failures) |
| 100750-100758 | UniFi | AP kernel (802.11 auth/assoc, DNS timeouts, VLAN failures, DHCP-SM traces, wlan errors) |
| 100770-100778 | UniFi | USW-Flex 2.5G + UPS Tower (port links, inform failures + persistence L7, heartbeats) |
| 100800-100806 | MikroTik | DHCP bindings (assigned/deassigned/offering), debug option dump, iface links + flapping L8 |
| 100820-100821 | Web | Malformed requests / scanner probes (single L5, repeated L8) |
| 100840-100858 | journald | ZFS zed (errors L9, burst L12), Proxmox backups (error L8), CRON, qemu-ga, LibreNMS, chronyd |
| 100900-100910 | Stormshield | Traffic (allowed L1 / blocked L3), SSL (blocked L4), IPS alarm L6 / high-risk L10, auth L5, SSL-VPN L4, system, plugin |
| 100911-100912 | Stormshield | DHCP (all verbs L1; **DHCPACK = who-is-connected L3**, IP/MAC/hostname extracted) |
| 100913-100919 | Stormshield | Admin audit L5 / config change L8, IPsec VPN L4 / failure L8, ipsec/filter/auth stats L1 |
| 101000-101003 | Authentik | Base + periodic chatter pinned to L0 (health checks, worker scheduling, router refresh) |
| 101010-101022 | Authentik | Audit trail (login/logout L3, failed login L5 + brute force L10, app authorization L3, account/credential change L5, config change L5, impersonation L8, suspicious request L8, exceptions L6) |
| 101030-101034 | Authentik | HTTP access (all decoded L0, 401/403 L5, 404 L3 + scanner correlation L8, 5xx L5) |
| 101035-101042 | Authentik | Django security L4 + generic warn/error/critical mapping (L4/L5/L7) |

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

### UniFi UDM system syslog (debug mode)
| Field | Content | Example |
|-------|---------|---------|
| `program` / `pid` | Program re-extracted from the doubled-hostname line | `sudo` / `21901` |
| `srcuser` / `dstuser` | sudo: invoking user / target user | `uid` / `root` |
| `command` | sudo: command executed | `/usr/lib/uid-agent/scripts/apps_info.sh` |
| `ips.file` | IPS list whose update failed | `/run/ips/rules/tor.list.gz` |
| `mem.avail_pct` | earlyoom: available memory % | `35.05` |
| `systemd.unit` / `status` | systemd unit and outcome | `wifiman-proxy-cert.service` / `Succeeded` |

### UniFi AP kernel events
| Field | Content | Example |
|-------|---------|---------|
| `station.mac` | Client station MAC | `aa:bb:cc:dd:ee:01` |
| `wifi.iface` / `wifi.vap` | Radio interface / VAP index | `wifi2ap8` / `4` |
| `wifi.auth_alg` / `wifi.rssi` | 802.11 auth algorithm / RSSI | `2` / `52` |
| `dns.timeouts` | DNS timeouts counted for the station | `4` |
| `vlan.tag` | VLAN that failed to assign | `1` |
| `dhcp.trace` | DHCP state machine trace | `d-10-o-30-r-10-a` |
| `wlan.level` / `wlan.facility` | wlan message severity / facility | `E` / `ANY` |

### UniFi USW-Flex / UPS Tower (MCA)
| Field | Content | Example |
|-------|---------|---------|
| `device.name` | Device hostname | `USWFlex25GOffice` |
| `device.mac` / `device.model` / `device.fw` | Identity | `942a6f...` / `USW-Flex-2.5G-5` / `7.4.2.1039` |
| `port` / `status` | Switch port and link state | `2` / `down` |
| `status` (UPS) | Inform HTTP status | `503` |
| `mca.rc` / `mca.reason` | Inform failure code / reason | `7` / `Server Busy` |
| `url` | Controller inform URL | `http://192.168.0.2:8080/inform` |

### MikroTik DHCP bindings
| Field | Content | Example |
|-------|---------|---------|
| `dhcp.server` | DHCP server instance | `dhcp1` |
| `action` | Binding operation | `assigned` / `deassigned` |
| `srcip` / `srcmac` / `srchost` | Bound IP / MAC / hostname | `192.168.0.33` / `00:24:E4:...` / `laptop` |
| `dhcp.option` / `dhcp.value` | Debug dump option | `Host-Name` / `"Mac"` |
| `iface` / `status` / `speed` | Link transitions | `sfp-sfpplus11` / `down` / `10G` |

### Web malformed requests (scanner probes)
| Field | Content | Example |
|-------|---------|---------|
| `srcip` | Scanner source IP | `203.0.113.66` |
| `id` | HTTP status | `400` |
| `http.request_raw` | Raw binary payload (TLS handshake bytes) | `\x16\x03\x01...` |

### ZFS zed (journald)
| Field | Content | Example |
|-------|---------|---------|
| `zfs.class` | Event class | `io` / `data` / `io_failure` / `scrub_finish` |
| `zfs.pool` | Pool name | `rpool` |
| `zfs.eid` / `zfs.detail` | Event id / raw detail (err=6 ENXIO, err=28 ENOSPC...) | `6743` / `err=28 ...` |

### FortiGate (built-in decoder fields)
Wazuh's built-in FortiGate decoder extracts all native fields: `srcip`, `dstip`, `srcport`, `dstport`, `action`, `policyid`, `service`, `srcintf`, `dstintf`, `devname`, `logid`, `level`, and more. Our custom rules add context through enhanced descriptions that surface VPN tunnel names and traffic patterns.

### Stormshield SNS
| Field | Content | Example |
|-------|---------|---------|
| `srcip` / `dstip` / `srcport` / `dstport` / `protocol` | Connection 5-tuple | `10.0.0.24` / `203.0.113.67` / `56594` / `443` / `https` |
| `fw.action` | Firewall verdict (dynamic field) | `pass` / `block` |
| `srcuser` | Authenticated user (SSL-VPN / admin) | `jdoe` |
| `logtype` | SNS log family | `filter` / `alarm` / `vpn` / `server` |
| `sns.msg` | Event message | `OpenVPN connection detected` |
| `alarm.id` / `alarm.class` / `alarm.risk` | IPS alarm | `118` / `protocol` / `10` |
| `dhcp.event` / `dhcp.ip` / `dhcp.mac` / `dhcp.hostname` | DHCP lease (asset inventory) | `DHCPACK` / `10.0.0.69` / `00:11:22:33:44:bb` / `Laptop-01` |
| `http.method` / `http.status` | Protocol plugin (HTTP) | `GET` / `200` |
| `srcintf` / `dstintf` | Interfaces | `lan` / `wan` |

### Authentik (JSON plugin decoder — all keys extracted)
| Field | Content | Example |
|-------|---------|---------|
| `logger` | structlog logger — the routing key | `authentik.events.models` / `authentik.asgi` |
| `action` | Audit action (**Wazuh static field** — learning #19) | `login` / `login_failed` / `model_updated` |
| `client_ip` | Client IP of the audited action | `203.0.113.67` |
| `user.username` | Acting user (nested JSON) | `jdoe` |
| `context.username` | Attempted username on failed logins | `admin` |
| `context.auth_method` | How the user authenticated | `password` / `auth_webauthn_pwl` |
| `method` / `event` / `remote` | HTTP request: verb, path, client | `GET` / `/api/v3/...` / `203.0.113.67` |
| `level` | structlog severity | `info` / `warning` / `error` |

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

# UDM system (debug mode, doubled hostname): IPS list update failure (level 5)
echo 'Jul  1 00:51:16 UDM-Pro-Max-AC UDM-Pro-Max-AC ips-update.sh[2238648]: File checksum failed for /run/ips/rules/tor.list.gz.' | /var/ossec/bin/wazuh-logtest

# UDM system: sudo command trail (level 3)
echo 'Jul  1 18:55:15 UDM-Pro-Max-AC UDM-Pro-Max-AC sudo[21901]:      uid : PWD=/data ; USER=root ; COMMAND=/usr/bin/id' | /var/ossec/bin/wazuh-logtest

# UniFi AP kernel: 802.11 authentication frame (level 3)
echo 'Jul  1 10:06:47 AP-Office 9c05d6000001,U7-Pro-Wall-8.7.9+19401: kernel: wlan: [0:I:ANY] [UNSPECIFIED] vap-4(wifi2ap8): [aa:bb:cc:dd:ee:01]recv auth frame with algorithm 2 seq 1 rssi:52 minrssi:0' | /var/ossec/bin/wazuh-logtest

# UPS Tower (no syslog timestamp): controller inform failure (level 4)
echo 'UPS-Office 847848000001,UPS TOWER-1.5.0.378: MCA: HTTP Status = 503, content_length = 0' | /var/ossec/bin/wazuh-logtest

# MikroTik DHCP binding (level 3)
echo 'Jul  1 00:33:20 router dhcp1 assigned 192.168.0.33 for 00:24:E4:51:0D:F8 laptop' | /var/ossec/bin/wazuh-logtest

# Scanner probe on a public endpoint (level 5)
echo '203.0.113.66 - - [01/Jul/2026:14:33:39 +0200] "" 400 0 "-" "-"' | /var/ossec/bin/wazuh-logtest

# ZFS zed error (level 9)
echo 'Jun 30 14:50:31 pve zed[851820]: eid=6743 class=io pool='"'"'rpool'"'"' size=8192 offset=839904612352 priority=0 err=6 flags=0x200080 bookmark=259:128:0:11611' | /var/ossec/bin/wazuh-logtest

# Stormshield SNS: blocked traffic (level 3)
echo 'id=firewall time="2026-07-06 13:44:52" fw="SN000TESTFW00000" tz=+0200 startime="2026-07-06 13:44:52" pri=5 confid=01 slotlevel=2 ruleid=29 rulename="rule_2" srcif="Ethernet1" srcifname="lan" ipproto=udp dstif="Ethernet0" dstifname="wan" proto=dns_udp src=10.0.0.61 srcport=40638 srcportname=ephemeral_fw_udp srcmac=00:11:22:33:44:66 dst=198.51.100.1 dstport=53 dstportname=dns_udp dstname=resolver.example ipv=4 sent=0 rcvd=0 duration=0.00 action=block logtype="filter"' | /var/ossec/bin/wazuh-logtest

# Stormshield SNS: high-risk IPS alarm (level 10)
echo 'id=firewall time="2026-07-06 13:45:10" fw="SN000TESTFW00000" tz=+0200 startime="2026-07-06 13:45:09" pri=1 confid=01 slotlevel=2 ruleid=93 rulename="rule_1d" srcif="Ethernet1" srcifname="lan" ipproto=tcp proto=ssl src=10.0.0.20 srcport=64127 dst=203.0.113.61 dstport=443 ipv=4 action=block msg="Invalid SSL packet (Unknown SSL protocol)" class=protocol classification=0 alarmid=118 target=dst risk=10 logtype="alarm"' | /var/ossec/bin/wazuh-logtest

# Stormshield SNS: DHCPACK — who is connected (level 3, IP/MAC/hostname extracted)
echo 'id=firewall time="2026-07-06 13:45:51" fw="SN000TESTFW00000" tz=+0200 startime="2026-07-06 13:45:51" pri=6 service=dhcp msg="DHCPACK on 10.0.0.69 to 00:11:22:33:44:bb (Laptop-01) via igc6" logtype="system"' | /var/ossec/bin/wazuh-logtest
```

## Tested environment

- Wazuh 4.14.5 (3-VM cluster: server, dashboard, indexer)
- MikroTik CCR2004-1G-12S+2XS running RouterOS 7.x (plus CRS317/CRS305 switches)
- Ubiquiti UDM Pro Max / UDM SE running UniFi Network 10.4–10.5 and UniFi Protect 7.x — plus access points (U6-IW, U7-Pro, U7-Pro-Wall, U7-Pro-Max, U7-Mesh, UDB), switches (USW-Pro-Max-48, USW-Enterprise-24-PoE, USW-Flex 2.5G) and UPS Tower units on firmware 6.x–8.x
- Fortinet FortiGate 60E running FortiOS 7.x
- Proxmox VE + Proxmox Backup Server (journald collection through Wazuh agents)
- Syslog transport: UDP/514 via rsyslog
- Decoder/rule validation: a survey of 10.7M archived events over 48h with device syslog set to debug — coverage measured at **100% decoded** (0 events without a decoder) after this ruleset

> Versions move fast; these decoders are kept working across newer Wazuh, RouterOS and UniFi releases, so the exact versions above are a snapshot, not a hard requirement.

## Log anonymiser

`tools/sns-anonymize.py` builds shareable Stormshield sample corpora from production logs **without leaking personal data**. Firewall logs contain named users, client IPs and MACs, hostnames, certificate DNs and browsing destinations — so the tool anonymises **in situ** (on the box where the logs live, read-only) and lets only pseudonymised output leave the environment. This is how the Stormshield samples in this repo were derived.

- **Consistent, non-reversible pseudonyms** — same real value → same placeholder within a run (structure and correlations preserved), but the mapping is order-based and never written to disk.
- IPs → `10.x` (private) / TEST-NET (public), plus MACs, users → `user0001`, hostnames, rulenames, domains, interface zones and appliance serial → placeholders.
- **Hard-redacts** the high-risk free text: `arg="..."`, certificate DNs anywhere (incl. `remoteid=`), and destination intelligence (geo / IP reputation / URL category) on **both** `src*` and `dst*` sides.
- **Diversity sampling** keeps a few examples per `(logtype, action, field-shape)`, so the corpus stays compact and representative.
- **Refuses to emit** (exit 2) if any site marker survives — a belt-and-braces leak scan. Site-specific markers (org names, serials, internal subnets) live in an external `--deny-file`, never in the script, so the tool itself is safe to publish (see `tools/leak_markers.example.txt`).

```bash
# build an anonymised corpus from the manager's archive (read-only)
sudo tail -n 500000 /var/ossec/logs/archives/archives.json \
  | tools/sns-anonymize.py --deny-file leak_markers.txt > corpus_anon.txt
# re-scan an existing corpus without anonymising
tools/sns-anonymize.py --self-check --deny-file leak_markers.txt < corpus_anon.txt
```

Two tools ship in `tools/`:
- **`sns-anonymize.py`** — Stormshield-tuned (knows the SNS field names); used to derive the Stormshield samples in this repo.
- **`log-anonymize.py`** — **generic, works on any device/format**: universal IPv4 / IPv6 / MAC / e-mail scrubbing, certificate-DN redaction, `--redact-key NAME` to blank your format's user/host fields, optional `--scrub-fqdn`, and `--field` to pull a value out of JSON lines (e.g. `full_log`). This is the one to run before **[requesting a decoder](CONTRIBUTING.md)** for a device we don't cover yet.

## Roadmap

- [ ] JAMF Protect & Security Cloud integration
- [x] Fortinet VPN tunnel state monitoring — tunnel/phase-2 up/down with per-tunnel flapping correlation (rules 100440-100445)
- [x] UniFi threat/IDS event decoding (rules 100358-100359, 100383-100384)
- [x] UniFi AP direct logs — readable per-AP syslog (daemon+message), Wi-Fi client assoc/disassoc, fan/thermal telemetry (`unifi_ap.xml`, rules 100368-100372); needs symantec `decoder_exclude` (learning #15)
- [x] UniFi switch direct logs — readable per-switch syslog (`unifi_switch.xml`, rule 100380; exclude BNC decoders if present)
- [x] UniFi debug-mode full coverage — UDM system syslog (doubled hostname), AP kernel events, USW-Flex/UPS Tower (no timestamp); measured 100% decode rate over a 48h/10.7M-event survey
- [ ] More UniFi hardware coverage — we are limited by the devices we own; log samples from other UniFi models (UXG, UCG, Protect NVRs, other switch/AP families) are very welcome
- [x] Stormshield SNS decoding — all logtypes (traffic, SSL, IPS alarms, auth, SSL-VPN, IPsec VPN, admin audit, DHCP asset inventory, periodic stats), rules 100900-100919
- [x] In-situ log anonymiser for building shareable sample corpora without leaking personal data (`tools/sns-anonymize.py`)
- [x] Generic, format-agnostic log anonymiser for any platform (`tools/log-anonymize.py`) — IPv4/IPv6/MAC/e-mail/DN scrubbing, `--redact-key`, `--scrub-fqdn`, deny-file
- [x] Community decoder-request workflow — submit anonymised logs via a GitHub issue template ([`CONTRIBUTING.md`](CONTRIBUTING.md))
- [x] Authentik IdP — structlog JSON via the Docker journald driver; audit trail with compliance tagging, brute-force + scanner correlations (rules 101000-101042)
- [ ] Propose the UniFi and Stormshield decoders upstream (Wazuh ruleset repository)
- [ ] Dashboard templates for OpenSearch/Kibana

## Contributing

PRs welcome — and you don't have to write a decoder yourself. **[Open a decoder request](../../issues/new?template=decoder-request.yml)** with a few **anonymised** log samples (run them through [`tools/log-anonymize.py`](#log-anonymiser) first — raw logs contain personal data) and we'll build one. See **[CONTRIBUTING.md](CONTRIBUTING.md)** for both paths (requesting vs. contributing) and the anonymisation requirement.

## License

MIT License — Use freely, attribution appreciated.

## Credits

Built by [Astier Consulting](https://www.astier-consulting.fr) with assistance from Claude (Anthropic).
