# Contributing to TIF

Thank you for your interest in contributing!

## Development Setup

```bash
git clone https://github.com/cvemula1/tif
cd tif
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/ -v
pytest tests/ --cov=tif --cov-report=term-missing  # with coverage
```

## Linting

```bash
ruff check tif/
ruff format tif/   # auto-format
```

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/) for automatic versioning:

| Prefix | Effect |
|--------|--------|
| `feat: ...` | Minor version bump (new feature) |
| `fix: ...` | Patch version bump (bug fix) |
| `perf: ...` | Patch version bump (performance) |
| `feat!: ...` or `BREAKING CHANGE:` | Major version bump |
| `docs:`, `chore:`, `ci:`, `test:` | No version bump |

Examples:
```
feat: add --only-fixable flag to reduce alert fatigue
fix: handle missing CVSS score in Grype output
feat!: rename Trust Card schema field (breaking change)
```

## Pull Request Process

1. Fork the repo and create a branch from `main`
2. Add tests for new behaviour
3. Ensure `pytest` and `ruff check` pass
4. Open a PR with a clear description of the change

## Adding a New Trust Gate

1. Create `tif/validators/<name>.py` with a function returning `(DataClass, GateResult)`
2. Register the gate in `tif/core/verifier.py`
3. Add toggle flag in `tif/cli.py` (`--skip` choices)
4. Add tests in `tests/test_<name>.py`

## Adding a New Policy Pack

1. Add `tif/policies/packs/<name>.rego` with standard TIF policy structure
2. Register pack name in `tif/policies/engine.py` `list_policy_packs()` and `_eval_builtin()`
3. Add tests in `tests/test_policy.py`

## Reporting Issues

Use [GitHub Issues](https://github.com/cvemula1/tif/issues). For security vulnerabilities, see [SECURITY.md](SECURITY.md).
