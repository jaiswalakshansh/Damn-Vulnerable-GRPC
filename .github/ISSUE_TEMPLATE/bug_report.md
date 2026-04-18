---
name: Bug report
about: Something inside the *framework* (not the intentional vulnerabilities!) is broken
title: "[bug] "
labels: bug
---

## Is this about an intentional vulnerability?

DVGRPC ships with 14 deliberate vulnerabilities.  If your "bug" is that
`admin:admin123` logs in, or that SQL injection works — that is expected
behaviour, not a bug.  Please close the issue.

## Describe the bug

<!-- What went wrong? What did you expect to happen? -->

## Reproduction

- [ ] I ran the server via Docker (`make up`)
- [ ] I ran the server locally (`make run`)

```bash
# commands that reproduce the issue
```

## Environment

- OS / Arch:
- Docker version:
- Python version:
- DVGRPC commit / tag:

## Logs

```
<paste relevant logs here>
```
