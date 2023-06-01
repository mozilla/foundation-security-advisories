import os
import sys

from cvelib.cve_api import CveApi
from requests import HTTPError

cve_api = CveApi(
    username=os.getenv("CVE_USER"),
    org=os.getenv("CVE_ORG"),
    api_key=os.getenv("CVE_API_KEY"),
    env=os.getenv("CVE_ENV"),
)


def main():
    for cve_advisory in cve_api.list_cves(state="RESERVED"):
        cve_id = cve_advisory["cve_id"]
        print(f"-> Rejecting {cve_id}")
        try:
            cve_api.move_to_rejected(cve_id)
        except HTTPError as e:
            raise Exception(f"Failed to reject {cve_id}, {e.response.text}")


if __name__ == "__main__":
    sys.exit(main())
