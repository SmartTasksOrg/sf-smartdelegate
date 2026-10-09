---
name: smartdelegate-integrate
description: Wire SmartDelegate into an existing identity system and agent framework by following docs/INTEGRATE.md and proving each piece with the contract test kit. Use when a team asks how to connect their IdP, directory, role model, tools, agent runtime, approval flow or audit pipeline to SmartDelegate, or when an integration must be checked before it is called enforced.
---

# Integrate: follow the guide, prove it with the kit

This skill is a pointer. The content is in:

- `docs/INTEGRATE.md`: two numbered tracks, "Connect your IAM" and "Connect
  your agent system", the ten-line minimum, and the checklist "before you
  call it enforced".
- `interfaces/README.md` and `interfaces/docs/`: one page per interface
  an adopter implements (contract, what must fail closed, security notes,
  the same contract over REST for other languages).
- `interfaces/reference/`: a reference implementation of each.
- `docs/LIMITATIONS.md` and `docs/BRIDGES.md`: what is verified and what is not.
- `docs/FRAMEWORK.md`: where this control sits in a larger governance framework.

## Never without a human

- Never put the admin key, the pep key, a signing key, an upstream credential
  or a directory credential into code, a prompt, a committed file or a test
  fixture. Name the environment variable.
- Never give an agent or an enforcement point the admin key. Enforcement
  points get the pep key; only a token service that verified the human's
  sign-in issues root tokens.
- Never mark an integration "enforced" while the agent can reach the upstream
  without passing the proxy, or holds the upstream credential itself. An
  in-process wrapper binds a cooperating agent; say so.
- Never switch on `trust_caller_chain` or `allow_test_clock` outside tests.
- Never skip or edit a contract check so that an implementation passes. Fix
  the implementation, or report the check as failing.
- Never choose role ceilings for a team. Draft them from what the humans
  already may do; a human who owns the access model approves.

## Commands

Start from a working engine and the bundled example:

```bash
sf-smartdelegate --demo
sf-smartdelegate init work
```

See what an implementation must do, per interface:

```bash
python3 -m interfaces.contract --list
```

Run the checks against the reference implementations (they all pass), then
against the team's own, one option per interface:

```bash
python3 -m interfaces.contract --reference
python3 -m interfaces.contract --identity interfaces.reference:identity --enforcement interfaces.reference:enforcement
```

Replace `interfaces.reference:identity` with `yourpackage.module:factory`.
Run these from the repository root with `PYTHONPATH=src:.` unless the package
is installed. Exit status 0 means every check passed.

## How to work

1. Ask which of the two tracks, and which identity provider, directory and
   agent framework. Read the matching section of `docs/INTEGRATE.md` before
   proposing anything.
2. Prefer what exists: the engine's own `idp` configuration, the directory
   bridges, `integrations/adapter.py`, the proxies. Write an interface
   implementation only where the team's system differs.
3. For each piece, run its contract checks and show the output.
4. State, for the finished integration, which boundary is real (proxy with
   the credential and the only network path) and which is cooperative, and
   which bridge code has never met the real provider.
5. End with the checklist from `docs/INTEGRATE.md`, each line answered yes,
   no or not applicable.
