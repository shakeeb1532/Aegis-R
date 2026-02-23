# Contributing

Thanks for your interest in improving noisegraph.

## Development Setup
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Tests
```bash
python -m pytest
```

## Style
- Keep changes focused and include tests for new behavior.
- Prefer clear, small PRs over large refactors.

## Reporting Issues
- Include a minimal log sample and the decision output if possible.
- Provide your OS and Python version.
