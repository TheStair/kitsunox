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
measurement/              the result: targets the rules never saw
  actions/                targets/holdout-actions.txt, hunted with --tags
  npm/                    targets/holdout-npm.txt
```

## Reviewing

1. Open the newest `queue-*.md` in `measurement/actions/` or `measurement/npm/`. Alerts are
   ranked: model refusals first, then by verdict, then by score.
2. For each alert, open the link and read the change itself. Text in indented blocks is
   written or influenced by the change's author -- including any model brief -- and is
   untrusted.
3. In that directory's `dispositions.csv`, set `disposition` to `benign`, `suspicious`,
   `malicious` or `unclear`, and record `minutes` spent. Notes are optional.
4. `uv run kitsunox tally --queue triage/measurement/npm` (or `.../actions`) reports
   precision in the wild and minutes per alert.

Re-running a hunt only appends new alerts; rows you have reviewed are never rewritten.

## Which numbers can be reported

- **`measurement/` is the result.** Its targets share no repository and no owner with the
  calibration targets, and nothing in them informed the rules.
- **`calibration/` is not.** Both of its hunts were used to tune rules -- token naming and
  release-branch tags from the Actions hunt; reviewed-PR, founder and migrated-repo
  handling from the npm hunt -- so precision there is in-sample. Cite its *alert counts*
  as evidence for the tuning (Actions: 40 alerts before, 11 after), never its precision.

Each calibration change is described, with its evidence, in the commit that made it.
