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
