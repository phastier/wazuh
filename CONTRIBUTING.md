# Contributing

Two ways to help — both start with **anonymising any log you share**.

## Request a decoder for a device we don't cover yet

Open a **[Decoder request issue](../../issues/new?template=decoder-request.yml)** and paste a few **anonymised** sample lines per event type.

> ⚠️ **Never paste raw production logs.** They contain personal data — usernames,
> client IPs, MACs, e-mail addresses, hostnames, certificate DNs. Anonymise first:
>
> ```bash
> # generic — works on any format; --redact-key blanks your user/host fields
> your-logs | tools/log-anonymize.py --deny-file markers.txt \
>     --redact-key user --redact-key host > shareable.txt
> ```
>
> `tools/log-anonymize.py` maps IPs/MACs/e-mails consistently, redacts certificate
> DNs, scrubs your site markers (from `--deny-file`, see `tools/leak_markers.example.txt`)
> and **refuses to emit** if a marker survives. It never writes a reverse mapping,
> but **you remain responsible for reviewing the output** before posting it.

Tell us the vendor/model, how the logs reach Wazuh (syslog vs. agent file), and
which fields/events matter (what should alert vs. stay telemetry).

## Contribute a decoder / rules (PR)

1. **English only** — descriptions, comments, groups. This ruleset is meant to be shared internationally.
2. **No client/production data** — decoders, rules and README examples use synthetic values (TEST-NET `192.0.2.0/24` / `198.51.100.0/24` / `203.0.113.0/24`, fake users/hostnames). Run a leak scan before committing:
   ```bash
   grep -rniE "<your-org>|<your-domains>|<internal-subnets>" decoders/ rules/ README.md
   ```
3. **Pick a free rule-ID range** — see the *Rule IDs* table in the README; don't collide with existing ranges.
4. **Follow the hard-won patterns** — read *Key technical learnings* in the README (one child decoder per parent, `<field>` matches are substring so anchor them, static-field pitfalls, base rule at level 3, etc.).
5. **Validate before you push**:
   ```bash
   sudo /var/ossec/bin/wazuh-analysisd -t        # must exit 0
   printf '%s\n' '<sample>' | sudo /var/ossec/bin/wazuh-logtest   # decoder + rule fire as expected
   ```
6. Open a PR describing the device, the logtypes/events covered, and the levels chosen.

## License

By contributing you agree your work is released under this repository's MIT License.
