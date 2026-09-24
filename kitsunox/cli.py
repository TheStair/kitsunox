"""Command-line entry point. Thin by design — argument parsing only.

    kitsunox evaluate [--incidents-only|--control-only] [--tier2] [--out report.json]
    kitsunox check --repo owner/name (--sha SHA | --pr N)
    kitsunox scan --repo owner/name [--limit N]

Tier 2 costs money, so it never runs unless `--tier2` is passed explicitly.
"""

from __future__ import annotations

import argparse
import sys
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
            if finding.evidence:
                print(f"                 {finding.evidence[:100]}")
    else:
        print("\n  no findings")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    """Rank a repository's direct pushes. Needs the caller's own GITHUB_TOKEN."""
    owner, name = args.repo.split("/", 1)
    results = evaluate.scan_repo(owner, name, args.limit, progress=None if args.quiet else _progress)
    if not results:
        print("no direct pushes found", file=sys.stderr)
        return 1

    print(f"\n{args.repo} — {len(results)} direct pushes, ranked by score\n")
    print(f"  {'rank':>4}  {'score':>5}  {'ev':>3}  commit      rules")
    for rank, r in enumerate(results[: args.top], start=1):
        evidence_rules = [x for x in r.rule_ids if not x.startswith("context.")]
        flag = "*" if r.escalated else " "
        print(f"  {rank:>4}{flag} {r.total_score:>5}  {r.evidence_score:>3}  "
              f"{r.key.split('@')[-1]:10}  {','.join(evidence_rules) or '-'}")
    if len(results) > args.top:
        print(f"\n  ...{len(results) - args.top} more (raise --top to see them)")
    print("\n  * = above the Tier 2 escalation threshold")
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

    sc = sub.add_parser("scan", help="rank a repository's direct pushes by score")
    sc.add_argument("--repo", required=True, metavar="owner/name")
    sc.add_argument("--limit", type=int, default=200, help="commits to examine")
    sc.add_argument("--top", type=int, default=25, help="rows to print")
    sc.add_argument("--quiet", action="store_true")
    sc.set_defaults(func=_cmd_scan)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
