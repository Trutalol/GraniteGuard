# Working together

## Branches
- `main` always runs. Never push broken code to it.
- Work on a branch named after your area: `p1/feature-name`, `p2/feature-name`, `p3/feature-name`.
- Open a pull request into `main`; one teammate glances at it before merging.

## Commits
Small and often. Start the message with your area: `pipeline: add EPSS momentum query`.

## Stay in your lane
- Edit your own folder freely.
- Changes to `shared/` (especially `contracts.py`) need a heads-up in the group chat first,
  because they can break the other two people.

## Secrets and data
- Keys go in `.env` only. `.env` is gitignored. Add new variable names to `.env.example`.
- Big CSVs (the 6.4M-row exploit signals) go in `data/raw/` and are **not committed**.

## Before you push
```bash
pytest
```

## Daily check-in (5 minutes)
1. What I finished
2. What I'm doing next
3. What I'm blocked on / what I need from someone
