# Triage

Where hunts deliver work to the investigator, and where the investigator's verdicts become
results.

```
calibration/              rules were tuned against these -- NOT reportable as results
  actions/
    calibration-raw/      first Actions hunt, before any tuning (40 alerts)
    queue-*.md            after tuning token and tag rules (11 alerts)
    tags.json             release-tag snapshot for targets/actions.txt
  npm/                    first npm hunt (25 alerts), before the AV-800 fixes
  round2/                 the first holdout (targets/holdout-*.txt), demoted 2026-10-26
    actions/, npm/        as hunted on 2026-10-08, with briefs: 17 alerts
    actions-fixed/,       the same targets re-hunted after the round-2 fixes
    npm-fixed/
measurement/              the result: targets/holdout2-*.txt, never looked at before hunting
  actions/                hunted with --tags
  npm/
```

## Reviewing

1. Open the newest `queue-*.md` in `measurement/actions/` or `measurement/npm/`. Alerts are
   ranked: model refusals first, then by verdict, then by score. Each rule appears once,
   with its strongest hit first and a count of the rest.
2. For each alert, open the link and read the change itself. Text in indented blocks is
   written or influenced by the change's author -- including any model brief -- and is
   untrusted.
3. In that directory's `dispositions.csv`, set `disposition` to `benign`, `suspicious`,
   `malicious` or `unclear`, and record `minutes` spent. Notes are optional.
4. `uv run kitsunox tally --queue triage/measurement/npm` (or `.../actions`) reports
   precision in the wild and minutes per alert.

Re-running a hunt only appends new alerts; rows you have reviewed are never rewritten.

## Which numbers can be reported

- **`measurement/` is the result.** Its targets (`targets/holdout2-*.txt`) share no
  repository and no owner with any earlier list, and nothing in them informed the rules.
- **`calibration/` is not.** Every hunt in it was used to tune rules, so precision there is
  in-sample. Cite its *alert counts* as evidence for the tuning, never its precision:
  - round 1, Actions: 40 alerts before, 11 after (token naming, release-branch tags);
  - round 1, npm: reviewed-PR, founder and migrated-repo handling;
  - round 2, both: 17 alerts on the first holdout, traced to five rule defects; see
    `docs/Story.md` for the before/after.

The first holdout was demoted because reading its queue exposed those defects, and fixing
them made it in-sample. That is the protocol working, not failing: a holdout is spent the
moment it is tuned on, and a fresh one replaces it.

Each calibration change is described, with its evidence, in the commit that made it.
