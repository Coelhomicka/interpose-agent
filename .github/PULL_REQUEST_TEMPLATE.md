## What this changes

<!-- One paragraph. What behavior is different after this PR? -->

## Why

<!-- Link the issue if there is one: Fixes #123 -->

## Trust boundary

Does this change any of the following?

- [ ] The order in which policy is evaluated relative to secret resolution
- [ ] What a managed child process receives in its environment
- [ ] What an API endpoint, CLI command, or log line outputs
- [ ] How policies are sourced or granted
- [ ] What crosses between the trusted and untrusted zones

**If any box is checked**, this PR needs a linked issue with an agreed design, and
[`docs/en/THREAT_MODEL.md`](../docs/en/THREAT_MODEL.md) must be updated to match.

## Checklist

- [ ] `pytest` passes
- [ ] `ruff check .` is clean
- [ ] Behavior changes are covered by a test — for a fix, one that fails without it
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`
- [ ] Documentation updated if behavior or guarantees changed
- [ ] No resolved secret value is logged, printed, or formatted anywhere in the diff

## Platforms tested

- [ ] Windows
- [ ] Linux
- [ ] macOS

<!-- Windows AppContainer tests skip on other platforms; a skip is expected, not a failure. -->
