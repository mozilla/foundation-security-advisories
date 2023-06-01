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
    owned_cve_ids, published_cve_id_dates = get_owned_cve_ids()
    local_cve_advisories: dict[str, CVEAdvisory] = get_local_cve_advisories()

    for cve_id in local_cve_advisories:
        cve_advisory = local_cve_advisories[cve_id]
        if cve_id.startswith("MFSA-RESERVE"):
            print_cve_step(cve_id)
            if not replace_cve_id(cve_advisory):
                continue
            cve_id = cve_advisory.id
            owned_cve_ids.append(cve_id)

        if cve_id not in owned_cve_ids:
            # if cve_id.startswith("CVE"):
            #     print_cve_step(cve_id)
            #     print(f"Warning: Skipping {cve_id} because we do not own it")
            continue

        if cve_id not in published_cve_id_dates:
            print_cve_step(cve_id)
            publish_cve(cve_advisory.id, cve_advisory.to_json_5_0())
        else:
            try_update_published_cve(
                local_cve=cve_advisory,
                local_date=cve_advisory.newest_instance.file_last_modified,
                remote_date=published_cve_id_dates[cve_id],
            )

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
