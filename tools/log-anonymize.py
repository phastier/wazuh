#!/usr/bin/env python3
"""
Generic log anonymiser — pseudonymise logs from ANY device/format before
sharing them (e.g. to request a new decoder) WITHOUT exposing personal data.

Firewall / network / MDM logs routinely contain personal data (usernames,
client IPs, MACs, hostnames, e-mail addresses, certificate DNs). Run this on
the machine where the logs live and share only the pseudonymised output.

What it does (format-agnostic, applied to every line):
  - IPv4  -> 10.x (private) / TEST-NET (public), loopback/zeros kept
  - IPv6  -> 2001:db8::N (documentation range), best-effort
  - MAC   -> 02:00:00:xx:xx:xx (locally-administered), consistent
  - e-mail-> anon@example
  - certificate DN runs (C=/O=/OU=/CN=...) -> [REDACTED-DN]
  - --redact-key NAME : blank the value of key=value and "NAME":"value" fields
                        (repeatable — use for your format's user/host fields)
  - --scrub-fqdn      : map hostnames/FQDNs -> hostNNNN.example (aggressive, opt-in)
  - --deny-file FILE  : site markers (org names, serials, subnets) scrubbed and
                        REFUSED in the output (belt-and-braces leak scan)
Mappings are consistent within a run (same input -> same placeholder) but
order-based, with NO reverse table written anywhere. Refuses to emit (exit 2)
if any deny marker or a residual e-mail survives.

Read-only. Never touches the network. The script is client-agnostic.

Usage:
  ./log-anonymize.py --deny-file markers.txt < mylogs.txt > shareable.txt
  ./log-anonymize.py --redact-key user --redact-key host < app.log > out.txt
  cat archives.json | ./log-anonymize.py --field full_log > out.txt   # extract JSON field
  ./log-anonymize.py --self-check --deny-file markers.txt < out.txt    # scan only
"""
import sys, re, json, argparse

DENY = []

class Mapper:
    def __init__(self, fmt): self.fmt=fmt; self.n=0; self.d={}
    def get(self, real):
        if real not in self.d:
            self.n += 1; self.d[real] = self.fmt(self.n)
        return self.d[real]

KEEP_IPS = {'0.0.0.0', '127.0.0.1', '255.255.255.255'}
def _priv4(ip):
    try: o = [int(x) for x in ip.split('.')]
    except ValueError: return True
    return o[0] in (10, 127) or (o[0]==172 and 16<=o[1]<=31) or (o[0]==192 and o[1]==168)
_p4 = Mapper(lambda n: "10.%d.%d.%d" % ((n>>16)&255, (n>>8)&255, n&255))
_POOLS = ['198.51.100', '203.0.113', '192.0.2']       # TEST-NET-1/2/3 (RFC5737)
class _Pub4:
    def __init__(self): self.n=0; self.d={}
    def get(self, ip):
        if ip not in self.d:
            self.d[ip]="%s.%d"%(_POOLS[(self.n//254)%3], (self.n%254)+1); self.n+=1
        return self.d[ip]
_pub4=_Pub4()
def map_ip4(ip):
    if ip in KEEP_IPS: return ip
    return _p4.get(ip) if _priv4(ip) else _pub4.get(ip)

_ip6 = Mapper(lambda n: "2001:db8::%x" % n)            # RFC3849 documentation range
mac  = Mapper(lambda n: "02:00:00:%02x:%02x:%02x" % ((n>>16)&255, (n>>8)&255, n&255))
host = Mapper(lambda n: "host%04d.example" % n)

IPV4  = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
MAC   = re.compile(r'\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b')
# IPv6: full 8-group, or any form containing '::' (won't collide with 6-group MAC)
IPV6  = re.compile(r'\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b'
                   r'|\b(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4})?'
                   r'|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}\b')
EMAIL = re.compile(r'\b[\w.+-]+@[\w.-]+\.\w+\b')
# certificate DN: 2+ consecutive attr=value tokens (C=FR, O=..., CN=...)
DN    = re.compile(r'\b(?:C|ST|L|O|OU|CN|DC|UID|emailAddress)=[^,;/"\s][^,;/"]*'
                   r'(?:[,;/]\s*(?:C|ST|L|O|OU|CN|DC|UID|emailAddress)=[^,;/"]*)+')
FQDN  = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')

def anonymize(s, redact_keys, scrub_fqdn):
    s = DN.sub('[REDACTED-DN]', s)
    for k in redact_keys:                       # key=value and "key":"value"
        s = re.sub(r'(\b%s=)("?)[^"\s,]*(\2)' % re.escape(k), r'\1[REDACTED]', s)
        s = re.sub(r'("%s"\s*:\s*)"[^"]*"' % re.escape(k), r'\1"[REDACTED]"', s)
    s = MAC.sub(lambda m: mac.get(m.group(0).lower()), s)      # MAC before IPv6
    s = IPV6.sub(lambda m: _ip6.get(m.group(0).lower()), s)
    s = IPV4.sub(lambda m: map_ip4(m.group(0)), s)
    s = EMAIL.sub('anon@example', s)
    if scrub_fqdn:
        s = FQDN.sub(lambda m: m.group(0) if m.group(0).endswith(('.example','.invalid','.test'))
                     else host.get(m.group(0).lower()), s)
    for mk in DENY:                             # site markers: token-bounded, quote-safe
        s = re.sub(r'[^\s"]*%s[^\s"]*' % re.escape(mk), '[REDACTED]', s, flags=re.I)
    return s

def get_line(raw, field):
    raw = raw.rstrip('\n')
    if not raw.strip(): return None
    if field and raw.lstrip()[:1] == '{':
        try: return json.loads(raw).get(field, '')
        except json.JSONDecodeError: return None
    return raw

def main():
    ap = argparse.ArgumentParser(description="Anonymise arbitrary logs before sharing.")
    ap.add_argument('--deny-file', help='newline-separated site markers to scrub & refuse')
    ap.add_argument('--redact-key', action='append', default=[], metavar='NAME',
                    help='blank the value of this key=value / "key":"value" field (repeatable)')
    ap.add_argument('--field', help='if input is JSON lines, extract this field (e.g. full_log)')
    ap.add_argument('--scrub-fqdn', action='store_true', help='also map hostnames/FQDNs (aggressive)')
    ap.add_argument('--no-dedup', action='store_true', help='keep duplicate lines')
    ap.add_argument('--self-check', action='store_true', help='only leak-scan stdin, no anonymise')
    a = ap.parse_args()

    deny = []
    if a.deny_file:
        with open(a.deny_file) as f:
            deny = [x.strip() for x in f if x.strip() and not x.startswith('#')]
    deny_re = re.compile('|'.join(re.escape(d) for d in deny), re.I) if deny else None
    DENY.extend(deny)

    if a.self_check:
        out = [l.rstrip('\n') for l in sys.stdin]
    else:
        out, seen = [], set()
        for raw in sys.stdin:
            line = get_line(raw, a.field)
            if line is None or line == '': continue
            an = anonymize(line, a.redact_key, a.scrub_fqdn)
            if not a.no_dedup:
                if an in seen: continue
                seen.add(an)
            out.append(an)

    leaks = []
    for ln in out:
        h = []
        if deny_re and deny_re.search(ln): h.append('deny-marker')
        if EMAIL.search(ln) and 'anon@example' not in ln: h.append('email?')
        if h: leaks.append((h, ln))

    if leaks:
        sys.stderr.write("%s — %d line(s) still contain markers:\n"
                         % ("LEAK-SCAN FAILED" if a.self_check else "REFUSING TO EMIT", len(leaks)))
        for h, ln in leaks[:20]: sys.stderr.write("  [%s] %s\n" % (','.join(h), ln[:160]))
        sys.exit(2)
    if a.self_check:
        sys.stderr.write("LEAK-SCAN: clean (%d lines)\n" % len(out)); sys.exit(0)
    for ln in out: print(ln)
    sys.stderr.write("OK: emitted %d anonymised lines\n" % len(out))

if __name__ == '__main__':
    main()
