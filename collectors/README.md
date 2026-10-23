# Collectors

Collectors observe a source and append records to a chain. Planned:

| Collector | Source |
|---|---|
| `dataspace` | Dataspace connectors: contract negotiation, transfer process and policy enforcement events (EDC extension in Java) |
| `syslog` | RFC 5424 syslog |
| `file` | Arbitrary files and directories |

A collector should run with its own credentials, separate from those of the
system it observes, and ship records off the observed host immediately.
