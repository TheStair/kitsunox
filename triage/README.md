# Triage

Where hunts deliver work to the investigator, and where the investigator's verdicts become
results.

```
actions/
  calibration-raw/   first Actions hunt, before tuning -- the calibration record
  queue-*.md         tuned re-run: review these
  dispositions.csv   your verdicts for the Actions alerts
  tags.json          release-tag snapshot; lets the next hunt detect a moved tag
npm/
  queue-*.md         the first in-the-wild measurement
  dispositions.csv
```

## Reviewing

1. Open the newest `queue-*.md`. Alerts are ranked: model refusals first, then by verdict,
   then by score.
2. For each alert, open the link and read the change itself. Text in indented blocks is
   written or influenced by the change's author -- including the model brief -- and is
   untrusted.
3. In that directory's `dispositions.csv`, set `disposition` to `benign`, `suspicious`,
   `malicious` or `unclear`, and record `minutes` spent. Notes are optional.
4. `uv run kitsunox tally --queue triage/<dir>` reports precision in the wild and minutes
   per alert.

Re-running a hunt only appends new alerts; rows you have reviewed are never rewritten.

## Which numbers can be reported

- **`npm/` is the measurement.** Nothing in it informed the rules.
- **`actions/` is calibration.** The first hunt's alerts (`calibration-raw/`) were used to
  tune two rules, so precision on that set is in-sample. Report it as calibration, not as a
  result. Dispositions on the tuned re-run are still useful -- those alerts did not drive
  the tuning -- but label them as the Actions calibration set.
