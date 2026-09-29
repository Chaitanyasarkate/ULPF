# Parser Definitions

Parser definitions are YAML files located in `parsers/` (mounted into the
backend container at `/app/parsers`). Each file declares a single source's
format, detection pattern, and the mapping from extracted fields to the
OCSF-based normalized schema.

## Planned parsers (added in Phase 3)

| Source | Format | Parser ID |
|--------|--------|-----------|
| cisco_asa | syslog | Firewall-Syslog-v1 |
| fortinet | json | Router-JSON-v1 |
| paloalto_cef | cef | IDS-CEF-v1 |
| vpn_concentrator | json | VPN-JSON-v1 |

## YAML schema (reference — implemented in Phase 3)

```yaml
source: cisco_asa
source_type: firewall
format: syslog          # syslog | json | cef | leef | csv | xml | keyvalue
parser_id: Firewall-Syslog-v1
parser_version: 1.0.0
pattern: '^(?P<...>).*$'
field_map:
  <extracted_field>: <ocsf_field>
```
