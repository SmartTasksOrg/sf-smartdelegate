# Contributing

Contributions are welcome. **Security problems do not go here**: see
[SECURITY.md](SECURITY.md).

## Before you start

- For anything larger than a fix, open an issue first and say what you want
  to change and why.
- By contributing you agree that your contribution is licensed under the
  licence in [LICENSE](LICENSE). There is no separate contributor agreement.
- Be decent: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Set up and run the checks

From a clone, Python 3.10 or later:

    python -m venv .venv
    # Windows PowerShell: .\.venv\Scripts\Activate.ps1   Linux/macOS: . .venv/bin/activate
    python -m pip install -e . pytest
    python -m pytest -q tests
    python scripts/check_install_lines.py

## Rules a change must keep

1. No secrets, keys, tokens or personal data in the repository.
2. No new runtime dependency without a maintainer's decision.
3. Say what was tested and what was not. Do not write that something works
   on a platform or at a scale it was not run on.
4. Install lines name only packages listed with `"registered": true` in
   `names.json`; `scripts/check_install_lines.py` enforces it in CI.
5. Add a line to [CHANGELOG.md](CHANGELOG.md) under "Unreleased".

## Pull requests

One topic per pull request. Describe what changes for a user, which tests
cover it, and the commands you ran with their results.
