# QA Task Coverage

`scripts/audit/acceptance_audit.py` parses `plan/1.txt` and checks that every `qa_agent` task is represented in QA-owned documentation. This file exists so task coverage can be maintained without editing the plan.

Current automated coverage is centered on:

- `T014` acceptance specification.
- `T029` OLLVM test inventory.
- `T036` behavior test inventory.
- `T037` baseline performance report inventory.
- `T046` randomness validation inventory.
- `T056` nested VM test inventory.
- `T067` automated anti-analysis and string metrics.
- `T080` dynamic-analysis validation inventory.
- `T097` Windows CI acceptance audit.
- `T106` Linux acceptance audit.
- `T116` Android emulator acceptance audit.
- `T117` Android hostile-environment acceptance audit.
- `T126` iOS logical acceptance audit.
- `T132` Windows GitHub Actions workflow audit.
- `T133` Android emulator CI inventory.
- `T134` macOS/iOS logic CI inventory.
- `T140` performance benchmark inventory.
- `T144` performance acceptance inventory.
- `T150` protected sample inventory.
- `T151` behavior report inventory.
- `T152` string report generation.
- `T153` automated anti-analysis report generation.
- `T154` hostile environment report generation.

Manual reverse-engineering review is intentionally not part of this coverage file because the requested QA gate is automated only.
