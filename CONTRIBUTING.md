# Contributing to signedhook

Thank you for considering a contribution. This document describes the
development workflow and the standards every change must meet.

## Development setup

```bash
git clone https://github.com/Odyntiq/signedhook.git
cd signedhook
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Quality gates (all required before any PR)

| Command | Gate |
|---|---|
| `pytest` | All tests pass; new behaviour needs new tests |
| `ruff check .` | Lint clean |
| `ruff format --check .` | Formatting clean |
| `mypy` | `--strict` clean (src) |
| `pip-audit` | No known vulnerabilities |

## Coding standards

- Python 3.10+; standard library only for the core (`signedhook[fastapi]`
  extras may import fastapi, guarded).
- Full type annotations; `from __future__ import annotations` in every
  module; `mypy --strict` must stay green.
- Security-critical code lives in ONE shared path (`_providers/base.py`,
  `_encoding.py`) — provider adapters must not reimplement comparison or
  decoding logic.
- Error messages never contain secrets, signatures, header values or
  payload contents. Use static reason strings.
- Log only structured, non-sensitive fields at DEBUG level.

## Commit and PR style

- Imperative, specific commit messages ("Add Twilio adapter for HMAC-SHA1
  signed_content"), logically grouped — no mega-commits.
- PRs must state what changed, why, and which gates were run.
- Update README/CHANGELOG when behaviour or the public API changes.

## Reporting bugs

Open a GitHub issue with: versions (python/signedhook), minimal
reproduction, expected vs actual behaviour. For security issues follow
SECURITY.md (private disclosure, no public issues).

## Licensing

By contributing you agree your work is released under the repository's MIT
license.
