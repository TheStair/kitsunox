"""Command-line entry point. Thin by design — argument parsing only.

    kitsunox evaluate [--incidents-only|--control-only] [--tier2] [--out report.json]
    kitsunox check --repo owner/name (--sha SHA | --pr N)
    kitsunox scan (--repo owner/name ... | --targets FILE ...) [--tags] [--brief] [--queue DIR]
    kitsunox tally [--queue DIR]

Tier 2 costs money, so it never runs unless `--tier2` (evaluate) or `--brief` (scan) is
passed explicitly, and `scan` briefs at most `--max-briefs` changes per hunt.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from kitsunox import evaluate, fetch, rules


def _progress(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _cmd_evaluate(args: argparse.Namespace) -> int:
    report = evaluate.evaluate(
        incidents=not args.control_only,
        control=not args.incidents_only,
        tier2=args.tier2,
        anonymize=args.anonymize,
        threshold=args.threshold,
        repos=args.repo or None,
        prs_per_repo=args.prs,
        pushes_per_repo=args.pushes,
        progress=None if args.quiet else _progress,
    )
    print(evaluate.format_summary(report))
    if args.out:
        path = evaluate.write_report(report, Path(args.out))
        print(f"\nReport written to {path}")
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    """Run one change through Tier 0 — the quick 'does this fire on X' check."""
    owner, name = args.repo.split("/", 1)
    try:
        if args.pr:
            matches = [c for c in fetch.fetch_merged_prs(owner, name, 50) if c.pr_number == args.pr]
            if not matches:
                print(f"PR #{args.pr} not found among recent merged PRs", file=sys.stderr)
                return 1
            change = matches[0]
        else:
            change = fetch.fetch_commit(owner, name, args.sha)
    except fetch.FetchError as exc:
        print(f"fetch failed: {exc}", file=sys.stderr)
        return 1

    findings = rules.scan(change)
    evidence = rules.evidence_score(findings)

    print(f"\n{change.repo} {change.sha[:10]}  ({change.source})")
    print(f"  author        {change.author}")
    if change.author_tenure_days is not None:
        print(f"  tenure        {change.author_tenure_days}d, {change.author_prior_commits} prior commits")
    print(f"  files         {len(change.files)}")
    print(f"  evidence      {evidence}   total {rules.score(findings)}")
    print(f"  escalates     {rules.should_escalate(findings)}")
    if findings:
        print("\n  findings:")
        for finding in sorted({f.rule_id: f for f in findings}.values(), key=lambda f: f.rule_id):
            where = f"  {finding.file_path}:{finding.line}" if finding.file_path else ""
            print(f"    [{finding.severity:8}] {finding.rule_id}{where}")
            if finding.precedent:
                print(f"                 precedent: {finding.precedent}")
            if finding.evidence:
                print(f"                 {finding.evidence[:100]}")
    else:
        print("\n  no findings")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    """Hunt target repositories and rank what they turn up. Needs the caller's own
    GITHUB_TOKEN; `--brief` also needs Anthropic credentials."""
    repos: list[str] = list(args.repo or [])
    for target_file in args.targets or []:
        try:
            repos += evaluate.load_targets(Path(target_file))
        except (OSError, ValueError) as exc:
            print(f"cannot read targets: {exc}", file=sys.stderr)
            return 2
    repos = list(dict.fromkeys(repos))  # de-duplicate, keep order
    if not repos:
        print("give at least one --repo or --targets file", file=sys.stderr)
        return 2

    queue = Path(args.queue) if args.queue else None
    results = evaluate.hunt(
        repos,
        limit=args.limit,
        prs=args.prs,
        tags=args.tags,
        brief=args.brief,
        max_briefs=args.max_briefs,
        snapshot_path=(queue / "tags.json") if (queue and args.tags) else None,
        progress=None if args.quiet else _progress,
    )
    if not results:
        print("no changes found", file=sys.stderr)
        return 1

    alerts = [r for r in results if r.escalated]
    print(f"\n{len(results)} changes across {len(repos)} repositories -- "
          f"{len(alerts)} escalated\n")
    print(f"  {'rank':>4}  {'score':>5}  {'ev':>3}  {'change':44}  evidence")
    for rank_no, r in enumerate(results[: args.top], start=1):
        evidence_rules = [x for x in r.rule_ids if not x.startswith("context.")]
        flag = "!" if r.refused else ("*" if r.escalated else " ")
        print(f"  {rank_no:>4}{flag} {r.total_score:>5}  {r.evidence_score:>3}  "
              f"{r.key[:44]:44}  {','.join(evidence_rules) or '-'}")
    if len(results) > args.top:
        print(f"\n  ...{len(results) - args.top} more (raise --top to see them)")
    print("\n  * escalated   ! the model declined to analyse it -- review first")

    if queue:
        stamp = datetime.now().strftime("%Y%m%d-%H%M")
        path = evaluate.write_triage(results, queue / f"queue-{stamp}.md",
                                     scanned=len(results), repos=repos)
        added = evaluate.merge_dispositions(results, queue / "dispositions.csv")
        cost = sum(r.cost_usd for r in results)
        print(f"\nQueue        {path}")
        print(f"Dispositions {queue / 'dispositions.csv'}  (+{added} new)")
        if args.brief:
            print(f"Brief cost   ${cost:.4f}")
    return 0


def _cmd_tally(args: argparse.Namespace) -> int:
    path = Path(args.queue) / "dispositions.csv"
    if not path.exists():
        print(f"no disposition log at {path} -- run `kitsunox scan --queue {args.queue}` first",
              file=sys.stderr)
        return 1
    print(evaluate.format_tally(evaluate.tally(path)))
    if args.summary:
        print(f"Summary      {evaluate.write_summary(path, Path(args.queue) / 'summary.md')}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="kitsunox", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    ev = sub.add_parser("evaluate", help="run the full evaluation and report")
    scope = ev.add_mutually_exclusive_group()
    scope.add_argument("--incidents-only", action="store_true", help="skip the control sample")
    scope.add_argument("--control-only", action="store_true", help="skip the ground truth")
    ev.add_argument("--tier2", action="store_true", help="also run Tier 2 (costs money)")
    ev.add_argument("--anonymize", action="store_true",
                    help="withhold repo and author names from Tier 2 (recognition ablation)")
    ev.add_argument("--threshold", type=int, default=None, help="override the escalation threshold")
    ev.add_argument("--repo", action="append", help="control repo (repeatable; default: the held-out set)")
    ev.add_argument("--prs", type=int, default=evaluate.DEFAULT_PRS_PER_REPO)
    ev.add_argument("--pushes", type=int, default=evaluate.DEFAULT_PUSHES_PER_REPO)
    ev.add_argument("--out", help="write the full JSON report here")
    ev.add_argument("--quiet", action="store_true")
    ev.set_defaults(func=_cmd_evaluate)

    ck = sub.add_parser("check", help="run one commit or PR through Tier 0")
    ck.add_argument("--repo", required=True, metavar="owner/name")
    target = ck.add_mutually_exclusive_group(required=True)
    target.add_argument("--sha")
    target.add_argument("--pr", type=int)
    ck.set_defaults(func=_cmd_check)

    sc = sub.add_parser("scan", help="hunt repositories and queue what escalates for review")
    sc.add_argument("--repo", action="append", metavar="owner/name", help="repeatable")
    sc.add_argument("--targets", action="append", metavar="FILE",
                    help="file of owner/name lines, # comments allowed; repeatable")
    sc.add_argument("--limit", type=int, default=evaluate.DEFAULT_HUNT_LIMIT,
                    help="direct pushes to examine per repository")
    sc.add_argument("--prs", type=int, default=0, help="also examine this many merged PRs per repo")
    sc.add_argument("--tags", action="store_true",
                    help="check release-tag integrity (GitHub Actions: tag rewrites, off-branch tags)")
    sc.add_argument("--brief", action="store_true",
                    help="Tier 2 analyst brief for the top escalated changes (costs money)")
    sc.add_argument("--max-briefs", type=int, default=evaluate.DEFAULT_MAX_BRIEFS,
                    help="cap on briefs per hunt")
    sc.add_argument("--queue", metavar="DIR",
                    help="write a triage queue and append to DIR/dispositions.csv")
    sc.add_argument("--top", type=int, default=25, help="rows to print")
    sc.add_argument("--quiet", action="store_true")
    sc.set_defaults(func=_cmd_scan)

    ta = sub.add_parser("tally", help="summarise reviewed dispositions: results in the wild")
    ta.add_argument("--queue", default="triage", metavar="DIR")
    ta.add_argument("--summary", action="store_true",
                    help="also write DIR/summary.md: the result and every alert's disposition")
    ta.set_defaults(func=_cmd_tally)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
