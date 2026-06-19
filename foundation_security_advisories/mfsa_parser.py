"""Parse MFSA advisory YAMLs into per-month Bugzilla bug ID sets for desktop Firefox."""
from __future__ import annotations

import glob
import os
import re
from collections import defaultdict
from datetime import datetime

import yaml

DESKTOP_FF_RE = re.compile(r"^Firefox\s+(\d+)(?:\.\d+)*$")
ANDROID_FF_RE = re.compile(r"^Firefox for Android\s+(\d+)(?:\.\d+)*$")


def parse_announced(announced) -> str | None:
    if announced is None:
        return None
    s = str(announced).strip()
    for fmt in ("%B %d, %Y", "%Y-%m-%d", "%B %d %Y"):
        try:
            return datetime.strptime(s, fmt).strftime("%Y-%m")
        except ValueError:
            continue
    m = re.match(r"(\d{4})-(\d{2})", s)
    return f"{m.group(1)}-{m.group(2)}" if m else None


def extract_bugs(bugs_field) -> tuple[list[str], bool]:
    """Return (bug_ids, is_rollup). Rollup CVEs have comma-separated IDs in the url."""
    ids: list[str] = []
    rollup = False
    for item in bugs_field or []:
        url = item.get("url") if isinstance(item, dict) else item
        if url is None:
            continue
        s = str(url).strip()
        if "," in s:
            rollup = True
        for tok in re.split(r"[,\s]+", s):
            if tok.isdigit():
                ids.append(tok)
    return ids, rollup


def firefox_majors(fixed_in, include_android: bool = False) -> list[str]:
    """Return major version strings (e.g. "134") for desktop Firefox in fixed_in."""
    if isinstance(fixed_in, str):
        fixed_in = [fixed_in]
    majors: list[str] = []
    for p in fixed_in or []:
        s = str(p).strip()
        m = DESKTOP_FF_RE.match(s)
        if m:
            majors.append(m.group(1))
            continue
        if include_android:
            m = ANDROID_FF_RE.match(s)
            if m:
                majors.append(m.group(1))
    return majors


def parse_advisories(
    repo_path: str,
    years: tuple[int, ...] = (2025, 2026),
    include_android: bool = False,
    group_by: str = "month",
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Group bug IDs by ``month`` (announced) or ``release`` (Firefox major version).

    With group_by="release", a bug shipped in multiple majors is counted in each.
    """
    by_group: dict[str, set[str]] = defaultdict(set)
    rollup_bugs: dict[str, set[str]] = defaultdict(set)

    paths: list[str] = []
    for y in years:
        paths += sorted(glob.glob(
            os.path.join(repo_path, "announce", str(y), f"mfsa{y}-*.yml")))
    if not paths:
        raise RuntimeError(f"no advisory YAMLs found under {repo_path}/announce/")

    for path in paths:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if not isinstance(doc, dict):
            continue

        majors = firefox_majors(doc.get("fixed_in"), include_android)
        if not majors:
            continue

        if group_by == "month":
            month = parse_announced(doc.get("announced"))
            keys = [month] if month else []
        elif group_by == "release":
            keys = sorted(set(majors), key=int)
        else:
            raise ValueError(f"unknown group_by: {group_by!r}")
        if not keys:
            continue

        for entry in (doc.get("advisories") or {}).values():
            if not isinstance(entry, dict):
                continue
            ids, rollup = extract_bugs(entry.get("bugs"))
            for key in keys:
                by_group[key].update(ids)
                if rollup:
                    rollup_bugs[key].update(ids)

    return by_group, rollup_bugs


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(
        description="Parse MFSA advisories and print per-month bug counts.")
    default_repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--repo-path", default=default_repo,
                    help="path to foundation-security-advisories checkout")
    ap.add_argument("--years", default="all",
                    help="comma-separated years to scan, or 'all' (default)")
    ap.add_argument("--include-android", action="store_true",
                    help="also include Firefox for Android advisories")
    ap.add_argument("--group-by", choices=("month", "release"), default="month",
                    help="bucket bugs by announced month or Firefox major release")
    ap.add_argument("--csv", action="store_true",
                    help="output CSV instead of a text table")
    args = ap.parse_args()

    if args.years == "all":
        years = tuple(sorted(
            int(d) for d in os.listdir(os.path.join(args.repo_path, "announce"))
            if d.isdigit()))
    else:
        years = tuple(int(y) for y in args.years.split(","))
    by_group, rollup_bugs = parse_advisories(
        args.repo_path, years,
        include_android=args.include_android, group_by=args.group_by)

    keys = sorted(by_group, key=int) if args.group_by == "release" else sorted(by_group)
    label = args.group_by
    rows = []
    for key in keys:
        total = len(by_group[key])
        rollup = len(rollup_bugs.get(key, set()))
        rows.append((key, total, rollup, total - rollup))

    if args.csv:
        import csv, sys
        w = csv.writer(sys.stdout)
        w.writerow([label, "total", "rollup", "individual"])
        w.writerows(rows)
    else:
        grand_total = grand_rollup = 0
        print(f"{label:>8}  {'total':>5}  {'rollup':>6}  {'individual':>10}")
        print("-" * 38)
        for key, total, rollup, individual in rows:
            grand_total += total
            grand_rollup += rollup
            print(f"{key:>8}  {total:>5}  {rollup:>6}  {individual:>10}")
        print("-" * 38)
        print(f"{'TOTAL':>8}  {grand_total:>5}  {grand_rollup:>6}  "
              f"{grand_total - grand_rollup:>10}")
