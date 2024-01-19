#!/usr/bin/env python3

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import sys
import subprocess

from foundation_security_advisories.common import (
    CVEAdvisory,
)
from foundation_security_advisories.common_cve import *


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
            elif cve_advisory.newest_instance.title.startswith("Memory safety bugs fixed")
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
