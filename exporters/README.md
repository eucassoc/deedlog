# Exporters

Exporters turn a verified chain into a package for a specific audience.
Planned:

| Exporter | Audience |
|---|---|
| `oscal` | Auditors: OSCAL assessment results, with records as observations |
| `legal` | Courts and counsel: evidence bodies, chain, checkpoints and a report |
| `ocsf` | SIEMs: OCSF findings |

Every package must include what an independent party needs to verify it
with `dlog verify`.
