# Examples

- `env.example`: allowed extra public ports.
- `report-mailinabox.en.txt`, `report-mailinabox.ru.txt`: text reports.
- `report-mailinabox.json`: `--format json` (FleetOps HealthResult).
- `report-mailinabox.v1.json`: `--format json-v1` (2.3 layout).

The reports come from the synthetic Mail-in-a-Box scenario in
`tests/e2e/test_stacks.py` (fake command outputs, `.example` domains,
documentation IP ranges); they are not output from a real server. Regenerate
with `TZ=UTC python3 tools/make_examples.py`.
