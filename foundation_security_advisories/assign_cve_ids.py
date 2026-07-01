#!/usr/bin/env python3

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import sys
import subprocess

from foundation_security_advisories.common import (
    CVEAdvisory,
    get_modified_files,
    parse_yml_file,
)
from foundation_security_advisories.common_cve import *


def find_placeholder_cve_ids(files):
    """MFSA-RESERVE placeholder CVE IDs found in the given .yml advisory files."""
    ids = []
    for fn in files:
        if not fn.endswith(".yml"):
            continue
        try:
            data = parse_yml_file(fn)
        except Exception:
            continue  # check_advisories will report parse errors
        for cve_id in data.get("advisories", {}):
            if cve_id.startswith("MFSA-RESERVE"):
                ids.append(cve_id)
    return ids


def prompt_main():
    staged = get_modified_files(staged_only=True)
    placeholders = find_placeholder_cve_ids(staged)

    if not placeholders:
        return 0

    print("\nThe following advisories have placeholder CVE IDs:")
    for cve_id in placeholders:
        print(f"  {cve_id}")
    print("CI will assign them automatically, but doing it locally also sets Bugzilla aliases.")

    # Open the terminal directly so interactive prompts work even when stdin is
    # redirected (e.g. in a git hook). Bail out silently if no terminal is attached.
    try:
        tty = open("/dev/tty", "r")
    except OSError:
        return 0

    import sys
    old_stdin = sys.stdin
    sys.stdin = tty
    try:
        if not os.getenv("CVE_ENV"):
            print("To assign locally: fill in .env, then: source .env && assign_cve_ids")
            return 0

        if not prompt_yes_no("\nAssign CVE IDs now?", default=False):
            return 0

        local_cve_advisories = get_local_cve_advisories(source_files=staged)
        for cve_id, cve_advisory in local_cve_advisories.items():
            if cve_id.startswith("MFSA-RESERVE"):
                print(f"\n-> {cve_id}")
                if replace_cve_id(cve_advisory):
                    try_set_bugzilla_alias(cve_id.split("-")[-1], cve_advisory.id)
                    for instance in cve_advisory.instances:
                        subprocess.run(["git", "add", instance.file_name])
    finally:
        sys.stdin = old_stdin
        tty.close()

    return 0


def main():
    # In this script, directly assign CVEs by default and do not ask for confirmation.
    if not os.getenv("PROMPT_ASK"):
        os.environ["PROMPT_CHOOSE_DEFAULT"] = "1"

    local_cve_advisories: dict[str, CVEAdvisory] = get_local_cve_advisories()

    for cve_id in local_cve_advisories:
        cve_advisory = local_cve_advisories[cve_id]
        if cve_id.startswith("MFSA-RESERVE"):
            print(f"\n-> {cve_id}")
            if replace_cve_id(cve_advisory):
                try_set_bugzilla_alias(cve_id.split("-")[-1], cve_advisory.id)
        elif cve_advisory.newest_instance.mfsa_id == os.getenv("ASSIGN_BUGZILLA_ANYWAYS", ""):
            # In the above, we have the bug id from the placeholder. Here we need to get it from the references
            if len(cve_advisory.newest_instance.references) == 1 and len(cve_advisory.newest_instance.references[0]) == 2 and \
                cve_advisory.newest_instance.references[0][1] is None and\
                cve_advisory.newest_instance.references[0][0].startswith("https://bugzilla.mozilla.org/show_bug.cgi?id="):
                bug_id = cve_advisory.newest_instance.references[0][0].replace("https://bugzilla.mozilla.org/show_bug.cgi?id=", "")
                try_set_bugzilla_alias(bug_id, cve_advisory.id)
            elif cve_advisory.newest_instance.title.startswith("Memory safety bugs fixed"):
                pass # Roll-up
            else:
                print(f"{cve_advisory.newest_instance.parent.id} didn't have an expected reference format so you have to set it manually.")

    if os.getenv("CI"):
        subprocess.run(
            [
                "git",
                "commit",
                "-m",
                f"Assign CVE ids",
            ]
        )
        subprocess.run(["git", "push"])


if __name__ == "__main__":
    sys.exit(main())
