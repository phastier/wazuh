#!/usr/bin/env python3
"""
Stormshield SNS log anonymiser — in-situ pseudonymisation for building and
sharing decoder sample corpora WITHOUT exposing production personal data
(usernames, IPs, MACs, hostnames, certificate DNs, destinations).

Reads Wazuh archives.json (or raw 'id=firewall ...' syslog lines) on stdin,
keeps only Stormshield events, then:
  - pseudonymises identifiers CONSISTENTLY within the run (order-based mapping,
    no reverse table is ever written to disk);
  - HARD-REDACTS high-risk free text (arg="...", certificate DNs anywhere,
    IPsec peer identities) and destination intelligence (geo / IP reputation /
    URL category, on both src* and dst* sides);
  - diversity-samples by (logtype, action, field-shape) to keep it compact;
  - refuses to emit (exit 2) if any residual leak marker survives.

Read-only: never writes to Wazuh, never touches the network. The script is
CLIENT-AGNOSTIC — site-specific markers (org names, serials, internal subnets)
live in an external --deny-file (see leak_markers.example.txt), never in here.
Data-protection rationale: these logs contain personal data (named users, IPs,
MACs), so anonymise them where they live and let only pseudonymised output out.

Usage:
  sudo tail -n 500000 /var/ossec/logs/archives/archives.json \
    | ./sns-anonymize.py --deny-file leak_markers.txt > corpus_anon.txt
  # only one syslog source (its archives.json "location" value):
  ... | ./sns-anonymize.py --deny-file leak_markers.txt --location 10.0.0.1 > corpus.txt
  ./sns-anonymize.py --self-check --deny-file leak_markers.txt < corpus.txt   # scan only
"""
import sys, re, json, argparse

DENY = []   # site-specific markers (from --deny-file); also scrubbed from free text

# ---------- consistent, order-based pseudonym allocators (no reverse table) ----
class Mapper:
    def __init__(self, fmt): self.fmt=fmt; self.n=0; self.d={}
    def get(self, real):
        if real not in self.d:
            self.n += 1; self.d[real] = self.fmt(self.n)
        return self.d[real]

KEEP_IPS = {'0.0.0.0', '127.0.0.1', '127.0.0.2', '255.255.255.255'}
def _is_private(ip):
    try: o = [int(x) for x in ip.split('.')]
    except ValueError: return True
    return (o[0] == 10 or (o[0] == 172 and 16 <= o[1] <= 31)
            or (o[0] == 192 and o[1] == 168) or o[0] == 127)

_priv = Mapper(lambda n: "10.%d.%d.%d" % ((n >> 16) & 255, (n >> 8) & 255, n & 255))
_POOLS = ['198.51.100', '203.0.113', '192.0.2']            # TEST-NET-1/2/3 (RFC5737)
class _PubIP:
    def __init__(self): self.n = 0; self.d = {}
    def get(self, ip):
        if ip not in self.d:
            self.d[ip] = "%s.%d" % (_POOLS[(self.n // 254) % 3], (self.n % 254) + 1)
            self.n += 1
        return self.d[ip]
_pub = _PubIP()
def map_ip(ip):
    if ip in KEEP_IPS: return ip
    return _priv.get(ip) if _is_private(ip) else _pub.get(ip)

mac_map  = Mapper(lambda n: "02:00:00:%02x:%02x:%02x" % ((n >> 16) & 255, (n >> 8) & 255, n & 255))
user_map = Mapper(lambda n: "user%04d" % n)
host_map = Mapper(lambda n: "host%04d" % n)
dom_map  = Mapper(lambda n: "domain%04d.example" % n)
zone_map = Mapper(lambda n: "zone%02d" % n)
rule_map = Mapper(lambda n: "rule%04d" % n)          # rulenames can be human-readable (may embed org/policy names)
GENERIC_ZONES = {'out', 'loopback', 'sslvpn', 'mgmt', 'HA', 'any', ''}

IP_RE     = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
MAC_RE    = re.compile(r'\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b')
EMAIL_RE  = re.compile(r'\b[\w.+-]+@[\w.-]+\.\w+\b')
SERIAL_RE = re.compile(r'\bSN[0-9A-Z]{8,}\b')                 # Stormshield appliance serials

def _sub_kv_q(key, s, repl):     # key="value"  (quoted)
    return re.sub(r'%s="([^"]*)"' % key, repl, s)

def anonymize(fulllog):
    s = fulllog
    # 1) hard-redact highest-risk free text
    s = re.sub(r'arg="[^"]*"', 'arg="[REDACTED]"', s)
    # 2) targeted key=value identifiers
    s = _sub_kv_q('user',   s, lambda m: 'user="%s"'   % (user_map.get(m.group(1)) if m.group(1) else ''))
    s = _sub_kv_q('domain', s, lambda m: 'domain="%s"' % (dom_map.get(m.group(1)) if m.group(1) else ''))
    s = re.sub(r'fw="[^"]*"', 'fw="SN000ANONFW00000"', s)
    s = _sub_kv_q('rulename', s, lambda m: 'rulename="%s"' % (rule_map.get(m.group(1)) if m.group(1) else ''))
    s = re.sub(r'\brulename=([^\s"]+)', lambda m: 'rulename=%s' % rule_map.get(m.group(1)), s)  # unquoted variant
    s = re.sub(r'srcname=(\S+)',     lambda m: 'srcname=%s'   % host_map.get(m.group(1)), s)
    s = _sub_kv_q('dstname', s, lambda m: 'dstname="%s"' % host_map.get(m.group(1)))
    s = re.sub(r'dstname=([^\s"]+)', lambda m: 'dstname=%s'   % host_map.get(m.group(1)), s)
    for k in ('srcifname', 'dstifname'):
        s = _sub_kv_q(k, s, lambda m, k=k: '%s="%s"' % (k, m.group(1) if m.group(1) in GENERIC_ZONES else zone_map.get(m.group(1))))
    # 2b) geo / IP-reputation / category — leave NO precise trace of who/where.
    #     Applies to BOTH sides: inbound traffic carries these on src* fields
    #     (srccountry/srccontinent/srciprep), outbound on dst*.
    s = re.sub(r'\b(\w*(?:iprep|country|continent))="[^"]*"', r'\1="[REDACTED]"', s)
    s = re.sub(r'\b(\w*(?:iprep|country|continent))=[^\s"]+', r'\1=[REDACTED]', s)
    s = re.sub(r'\bcat_site="[^"]*"', 'cat_site="[REDACTED]"', s)
    for k in ('remoteid', 'localid'):   # IPsec peer/self identity (cert DN / FQDN / keyid)
        s = re.sub(r'\b%s="[^"]*"' % k, '%s="[REDACTED]"' % k, s)
        s = re.sub(r'\b%s=[^\s"]+' % k, '%s=[REDACTED]' % k, s)
    # proto/portname sometimes embed the destination app after a hyphen
    # (https-google, mongodb-haa) -> keep the base protocol only
    s = re.sub(r'\b(proto|dstportname|srcportname)=([A-Za-z0-9_]+)-\S+', r'\1=\2', s)
    # 3) inside msg="...": redact certificate DN runs; anonymise dhcp hostname paren
    is_dhcp = 'service=dhcp' in s
    def _msg(m):
        # certificate DNs are the only msg values carrying key=value tokens;
        # hard-redact from the first such token to end of msg (kills O=/CN= and
        # any org name embedded between DN runs, e.g. "CN=Sub CA <org> Internal").
        inner = re.sub(r'\s*\b[A-Za-z]{1,20}=.*$', ' [REDACTED-DN]', m.group(1))
        if is_dhcp:
            inner = re.sub(r'\(([^)]+)\)', lambda h: '(%s)' % host_map.get(h.group(1)), inner)
        return 'msg="%s"' % inner
    s = _sub_kv_q('msg', s, _msg)
    # 3b) certificate DNs also live in NON-msg quoted fields (remoteid, localid,
    #     subject, ...) — redact any quoted value carrying a DN (CN=/OU=).
    s = re.sub(r'(\b\w+)="[^"]*\b(?:CN|OU)=[^"]*"', r'\1="[REDACTED-DN]"', s)
    # 4) global scrub of anything that still looks like an identifier
    s = IP_RE.sub(lambda m: map_ip(m.group(0)), s)
    s = MAC_RE.sub(lambda m: mac_map.get(m.group(0).lower()), s)
    s = EMAIL_RE.sub('anon@example', s)
    s = SERIAL_RE.sub('SN000ANONFW00000', s)
    # 5) final safety scrub: nuke any site-specific marker still present in free
    #    text (object names, CRL/identity names, ...). Token-bounded, quote-safe.
    for mk in DENY:
        s = re.sub(r'[^\s"]*%s[^\s"]*' % re.escape(mk), '[REDACTED]', s, flags=re.I)
    return s

# ---------- extraction / diversity sampling ------------------------------------
def full_log_of(line, location=None):
    line = line.strip()
    if not line: return None
    if line[0] == '{':
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            return None
        if location and o.get('location') != location:
            return None
        fl = o.get('full_log', '')
        return fl if fl.startswith('id=firewall') else None
    return line if line.startswith('id=firewall') else None

def shape(fl):
    lt = (re.search(r'logtype="([^"]*)"', fl) or [None, '?'])[1]
    ac = (re.search(r'\baction=(\w+)', fl) or [None, '-'])[1]
    keys = tuple(sorted(set(re.findall(r'(\b[a-zA-Z]+)=', fl))))
    return (lt, ac, keys)

def main():
    ap = argparse.ArgumentParser(description="Anonymise Stormshield SNS logs in-situ.")
    ap.add_argument('--deny-file', help='newline-separated site markers to scrub and refuse in output')
    ap.add_argument('--location', help='only process archives.json events whose "location" equals this value')
    ap.add_argument('--max-per-shape', type=int, default=3, help='keep at most N examples per (logtype, action, field-shape)')
    ap.add_argument('--self-check', action='store_true', help='only leak-scan stdin, no anonymise')
    a = ap.parse_args()

    deny = []
    if a.deny_file:
        with open(a.deny_file) as f:
            deny = [ln.strip() for ln in f if ln.strip() and not ln.startswith('#')]
    deny_re = re.compile('|'.join(re.escape(d) for d in deny), re.I) if deny else None
    DENY.extend(deny)   # feed the free-text scrub in anonymize()

    if a.self_check:
        out_lines = [l.rstrip('\n') for l in sys.stdin]
    else:
        seen = {}
        out_lines = []
        for line in sys.stdin:
            fl = full_log_of(line, a.location)
            if not fl: continue
            sig = shape(fl)
            if seen.get(sig, 0) >= a.max_per_shape: continue
            seen[sig] = seen.get(sig, 0) + 1
            out_lines.append(anonymize(fl))

    # leak-scan (defence in depth: explicit site markers + generic heuristics).
    # Site-specific subnets/org names belong in the --deny-file, not here.
    leaks = []
    for ln in out_lines:
        hits = []
        if deny_re and deny_re.search(ln): hits.append('deny-marker')
        if re.search(r'\bSN[0-9]{3}[A-Z][0-9]', ln): hits.append('serial?')        # Stormshield serial shape
        if EMAIL_RE.search(ln) and 'anon@example' not in ln: hits.append('email?')
        if hits: leaks.append((hits, ln))

    if a.self_check:
        if leaks:
            sys.stderr.write("LEAK-SCAN: %d suspicious line(s):\n" % len(leaks))
            for h, ln in leaks[:20]: sys.stderr.write("  [%s] %s\n" % (','.join(h), ln[:160]))
            sys.exit(2)
        sys.stderr.write("LEAK-SCAN: clean (%d lines)\n" % len(out_lines)); sys.exit(0)

    if leaks:
        sys.stderr.write("REFUSING TO EMIT — %d line(s) still contain markers:\n" % len(leaks))
        for h, ln in leaks[:20]: sys.stderr.write("  [%s] %s\n" % (','.join(h), ln[:160]))
        sys.exit(2)
    for ln in out_lines: print(ln)
    sys.stderr.write("OK: emitted %d anonymised lines (%d distinct shapes)\n"
                     % (len(out_lines), len(set(shape(l) for l in out_lines))))

if __name__ == '__main__':
    main()
