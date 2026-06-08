# Development

ZeroPath is a Python package with a CLI entry point. Use an isolated virtual
environment for local work.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
zeropath --help
```

The stable workflow to exercise during development is:

```bash
zeropath init
zeropath ingest --repo .
zeropath understand
zeropath hunt --mode critical --limit 5
zeropath prove <candidate-id> --backend foundry
zeropath judge <candidate-id>
zeropath report <candidate-id> --format code4rena
```

Generated ZeroPath state lives under `.zeropath/`. Foundry may also create
`out/`, `cache/`, and `broadcast/`; these are local artifacts and should not be
committed.
