import difflib
from glob import glob
import json
from os import path

from foundation_security_advisories.common_cve import get_local_cve_advisories


def main():
    errors = []

    yaml_files = glob("test/*.yml")
    filenames = [path[5:-4] for path in yaml_files]

    for filename in filenames:
        print(f"{filename}.yml", end="")
        advisories = get_local_cve_advisories([f"test/{filename}.yml"])

        actual = json.dumps(
            {cve_id: advisory.to_json()
             for cve_id, advisory
             in advisories.items()},
            indent=2,
            sort_keys=True
        )

        if path.isfile(f"test/{filename}.expected.json"):
            with open(f"test/{filename}.expected.json", "r") as f:
                expected = f.read()
        else:
            expected = ""

        if expected != actual:
            errors.append(f"{filename}.yml")

            diff = difflib.unified_diff(
                expected.split("\n"),
                actual.split("\n"),
                lineterm="",
                fromfile=f"Expected Result",
                tofile=f"Actual Result",
            )
            for line in diff:
                print(line)

            with open(f"test/{filename}.actual.json", "w") as f:
                f.write(actual)

            print(
                f"Use \"mv test/{filename}.actual.json test/{filename}.expected.json\" to update the expected result")
        else:
            print("Got expected result")

        print()

    if errors:
        print(f"Encountered errors in {errors}")
        exit(1)
    else:
        print("Got all expected results")
