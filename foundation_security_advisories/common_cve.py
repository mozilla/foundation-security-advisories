#!/usr/bin/env python3

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import sys
import subprocess
from datetime import datetime, timezone
from json import dumps
import difflib
from bisect import insort
import requests

from cvelib.cve_api import CveApi
from requests import HTTPError

from foundation_security_advisories.common import (
    get_all_files,
    parse_yml_file,
    CVEAdvisory,
    CVEAdvisoryInstance,
)

cve_api = CveApi(
    username=os.getenv("CVE_USER"),
    org=os.getenv("CVE_ORG"),
    api_key=os.getenv("CVE_API_KEY"),
    env=os.getenv("CVE_ENV"),
)

announced_cve_steps: list[str] = []


def print_cve_step(cve_id: str):
    if cve_id not in announced_cve_steps:
        print(f"\n-> {cve_id}")
        announced_cve_steps.append(cve_id)


def publish_cve(cve_id: str, cve_json: dict):
    """
    CVE Services: Publish the content for a already existing and given
    CVE-ID with the given data in CVE JSON format.
    """
    cve_json["containers"]["cna"]["references"].sort(
        key=lambda reference: reference["url"]
    )
    diff = difflib.unified_diff(
        "",
        dumps(cve_json, indent=2, sort_keys=True).split("\n"),
        lineterm="",
        fromfile=f"Remote (not yet published)",
        tofile=f"Local",
    )
    for line in diff:
        print(line)
    if not prompt_yes_no(f"\nShould this content be published for {cve_id}?"):
        print(f"Skipping {cve_id}")
        return False
    print(f"Publishing {cve_id}")
    try:
        cve_api.publish(cve_id, cve_json)
        # The timestamp on the API needs to be younger than the commit timestamp so that
        # the file does not get registered as modified.
        touch_cve_id(cve_id)
    except HTTPError as e:
        raise Exception(f"Failed to publish {cve_id}, {e.response.text}")


def get_cve(cve_id: str):
    """CVE Services: Get CVE for the given CVE-ID."""
    try:
        return cve_api.show_cve_record(cve_id)
    except HTTPError as e:
        raise Exception(f"Failed to publish {cve_id}, {e.response.text}")


def touch_cve_id(cve_id: str):
    """CVE Services: Update the timestamp of the given CVE-ID to the current date."""
    print(
        f"Updating timestamp on {cve_id} to current date {pretty_date(datetime.now(tz=timezone.utc).timestamp())}"
    )
    return cve_api._put(f"cve-id/{cve_id}").json()


def update_published_cve(cve_id: str, cve_json: dict):
    """CVE Servies: Update the content of the given CVE-ID with the given data in CVE JSON 5.1 format."""
    print(f"Updating {cve_id}")
    try:
        cve_api.update_published(cve_id, cve_json)
        # We need to update the timestamp on the CVE-ID itself, because that is what we use
        # later to check for modified files.
        touch_cve_id(cve_id)
    except HTTPError as e:
        raise Exception(f"Failed to update {cve_id}, {e.response.text}")


def try_update_published_cve(local_cve: CVEAdvisory, local_date: int, remote_date):
    """
    Check if there is a difference between the local and the remote CVE.
    If there is one, update the CVE.
    """
    remote_date_str = pretty_date(remote_date)
    local_date_str = pretty_date(local_date)
    if remote_date > local_date and not os.getenv("FORCE_UPDATE"):
        return
    print_cve_step(local_cve.id)
    # We need to modify the remote and local json a bit to make sure we only
    # detect a diff if something actually changed.
    remote_cve_json = get_cve(local_cve.id)
    remote_cve_json.pop("cveMetadata")
    remote_cve_json_container = remote_cve_json["containers"]["cna"]
    remote_cve_json_container.pop("providerMetadata")
    if "x_legacyV4Record" in remote_cve_json_container:
        remote_cve_json_container.pop("x_legacyV4Record")
    local_cve_json = local_cve.to_json()
    local_reference_urls = [
        local_reference[0]
        for local_instance in local_cve.instances
        for local_reference in local_instance.references
    ]
    # If there are references which we did not add automatically, we probably don't
    # want to remove them, so we move them to our to-be-published object.
    remote_extra_references = list(
        filter(
            lambda reference: not reference["url"] in local_reference_urls
            and all(
                not reference["url"].startswith(prefix)
                for prefix in [
                    "https://bugzilla.mozilla.org",
                    "https://www.bugzilla.mozilla.org",
                    "https://mozilla.org",
                    "https://www.mozilla.org",
                ]
            ),
            remote_cve_json["containers"]["cna"]["references"],
        )
    )
    local_cve_json["containers"]["cna"]["references"].extend(remote_extra_references)
    # Sort the references to make sure we detect the diff correctly.
    remote_cve_json["containers"]["cna"]["references"].sort(
        key=lambda reference: reference["url"]
    )
    local_cve_json["containers"]["cna"]["references"].sort(
        key=lambda reference: reference["url"]
    )
    # Include any other containers from the remote we do not know about (like "adp")
    for container_name in remote_cve_json["containers"].keys():
        if container_name not in local_cve_json["containers"].keys():
            local_cve_json["containers"][container_name] = remote_cve_json[
                "containers"
            ][container_name]

    diff = difflib.unified_diff(
        dumps(remote_cve_json, indent=2, sort_keys=True).split("\n"),
        dumps(local_cve_json, indent=2, sort_keys=True).split("\n"),
        lineterm="",
        fromfile=f"Remote",
        fromfiledate=remote_date_str,
        tofile=f"Local ",
        tofiledate=local_date_str,
    )
    is_unchanged = True
    for line in diff:
        print(line)
        is_unchanged = False
    if is_unchanged:
        # There seems to be no actual difference, lets update the
        # timestamp so that we won't be here again next time.
        print(f"--- Remote\t{remote_date_str}")
        print(f"+++ Local \t{local_date_str}")
        print(f"Not actual difference found for {local_cve.id}")
        touch_cve_id(local_cve.id)
        return
    if local_cve.year < 2023:
        if not prompt_yes_no(
            f"\nThis CVE lies before the cutoff year 2023. Should the content still be updated for {local_cve.id}?",
            default=False,
        ):
            print(f"Skipping {local_cve.id} because it lies before the cutoff year")
            touch_cve_id(local_cve.id)
            return False
    else:
        if not prompt_yes_no(f"\nShould this content be updated for {local_cve.id}?"):
            print(f"Skipping {local_cve.id}")
            return False
    update_published_cve(local_cve.id, local_cve_json)


def reserve_cve_id(year: str):
    """CVE Servies: Reserve a new CVE-ID for a given year and return that new id."""
    print(f"Reserving CVE-ID for year {year}")
    try:
        response = cve_api.reserve(1, False, year)
    except HTTPError as e:
        raise Exception(f"Failed to reserve CVE-ID, {e.response.text}")
    if (
        "cve_ids" not in response
        or len(response["cve_ids"]) != 1
        or "cve_id" not in response["cve_ids"][0]
    ):
        raise ValueError(f"API did not respond with valid CVE-ID")
    return response["cve_ids"][0]["cve_id"]


def get_owned_cve_ids():
    """
    CVE-Services: Get all the CVE-IDs owned by the current CNA. Returns a tuple containing:

    - A list of all the owned IDs, regardless of their state
    - A dictionary of all the IDs with the state `PUBLISHED`, mapped to the time
      they were last modified.
    """
    published_dates: dict[str, float] = {}
    owned_ids = []
    print("-> Fetching already owned CVE-IDs")
    for cve_advisory in cve_api.list_cves():
        cve_id = cve_advisory["cve_id"]
        owned_ids.append(cve_id)
        if cve_advisory["state"] == "PUBLISHED" or cve_advisory["state"] == "REJECTED":
            published_dates[cve_id] = parse_iso_date(cve_advisory["time"]["modified"])
        elif cve_advisory["state"] == "RESERVED":
            continue
        else:
            raise ValueError(f"Invalid CVE state '{cve_advisory['state']}'")
    return owned_ids, published_dates


def replace_cve_id(cve: CVEAdvisory):
    """
    Replace the id of a given `CVEAdvisory` with a new CVE-ID.
    Returns True if the id of the given advisory has been changed and False
    if it hasn't.
    """
    old_id = cve.id
    if not prompt_yes_no(f"Should a new CVE-ID be reserved to replace {old_id}?"):
        print(f"Skipping {old_id}")
        return False
    print(f"Replacing CVE-ID for {old_id}")
    new_id = reserve_cve_id(cve.year)
    print(f"Reserved {new_id}")
    cve.id = new_id
    for instance in cve.instances:
        with open(instance.file_name) as r:
            file_content = r.read().replace(old_id + ":", new_id + ":")
        with open(instance.file_name, "w") as w:
            w.write(file_content)
        if os.getenv("CI"):
            subprocess.run(["git", "add", instance.file_name])
    print(f"Renamed {old_id} to {new_id}")
    return True


def parse_iso_date(date_string: str):
    """
    Parse the given date string in the format used by CVE Servies
    and return the corresponding date as a unix timestamp.
    """
    return datetime.fromisoformat(date_string).timestamp()


def pretty_date(utc_timestamp: str):
    """
    Return the given Unix UTC timestamp as a string in the following format:
    %Y-%m-%d %H:%M:%S UTC
    """
    return datetime.fromtimestamp(utc_timestamp, timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def parse_bug(bug: dict):
    """
    Parse a single given bug from the advisory YAML, and return the
    corresponding URL and (optionally) description.
    """
    url = str(bug["url"])
    desc = str(bug["desc"]) if "desc" in bug else None
    if not url.startswith("http"):
        if "," in url:
            url = "https://bugzilla.mozilla.org/buglist.cgi?bug_id=" + url.replace(
                " ", ""
            ).replace(",", "%2C")
        else:
            url = "https://bugzilla.mozilla.org/show_bug.cgi?id=" + url
    return url, desc


def prompt_yes_no(question: str, default=True):
    if os.getenv("CI") or os.getenv("PROMPT_CHOOSE_DEFAULT"):
        return default
    try:
        response = input(question + (" (Y/n)" if default else " (y/N)"))
    except KeyboardInterrupt:
        exit(0)
    return response.strip().lower() in (["", "y", "yes"] if default else ["y", "yes"])


def get_local_cve_advisories():
    """
    Get all the CVE advisories located in this repository as `CVEAdvisory`
    objects. Returns a dictionary of all the local CVE-IDs mapped to
    their respective `CVEAdvisory` objects.
    """
    local_advisories: dict[str, CVEAdvisory] = {}
    print("\n-> Checking local files")
    for file_name in get_all_files():
        if not file_name.endswith(".yml"):
            continue

        file_data: dict = parse_yml_file(file_name)

        file_last_modified = int(
            subprocess.run(
                [
                    "git",
                    "log",
                    "--pretty=format:%at",
                    "-1",
                    "HEAD",
                    "--",
                    file_name,
                ],
                capture_output=True,
            ).stdout.strip()
        )

        if "advisories" in file_data:
            for cve_id in file_data["advisories"]:
                cve_data = file_data["advisories"][cve_id]
                if cve_id not in local_advisories:
                    year = int(cve_id.split("-")[-2])
                    local_advisories[cve_id] = CVEAdvisory(id=cve_id, year=year)
                for fixed_in in file_data["fixed_in"]:
                    product, version_fixed = fixed_in.rsplit(None, 1)
                    references = [parse_bug(bug) for bug in cve_data["bugs"]]
                    cve_instance = CVEAdvisoryInstance(
                        parent=local_advisories[cve_id],
                        title=cve_data["title"],
                        description=cve_data["description"].strip(),
                        reporter=cve_data["reporter"],
                        references=references,
                        mfsa_id=file_data["mfsa_id"],
                        product=product,
                        version_fixed=version_fixed,
                        file_name=file_name,
                        file_last_modified=file_last_modified,
                    )
                    # We want the instances to be sorted by the msfa id to avoid pushing updates
                    # to the API where the only thing that changes is the order of the instances.
                    insort(
                        local_advisories[cve_id].instances,
                        cve_instance,
                        key=lambda x: x.mfsa_id,
                    )
    return local_advisories


def try_set_bugzilla_alias(bug: str, cve_id: int):
    """
    Try to set the alias of the given bugzilla bug to the given CVE-ID.
    The bug number is supposed to come from the temporary MSFA-RESERVE-{year}-{id}
    IDs, where {id} potentially is a bugzilla bug number. All {id}s smaller than 100000
    will be ignored. Will return without error if anything fails.
    """
    try:
        # Check if we have a bugzilla API key available
        BUGZILLA_API_KEY = os.getenv("BUGZILLA_API_KEY")
        if not BUGZILLA_API_KEY:
            print(
                f"Skipping alias assignment for {cve_id} (bug {bug}) as no BUGZILLA_API_KEY was provided"
            )
            return
        # Make sure this is actually a number
        bug_number = int(bug)
        # Skip smaller numbers as there is a high chance these aren't any actual bugzilla bug numbers
        if bug_number < 100000:
            print(
                f"Skipping alias assignment for {cve_id} as '{bug_number}' does not seem to be a bug number"
            )
            return
        if not prompt_yes_no(
            f"Should '{cve_id}' be set as an alias for bug {bug_number} on bugzilla?"
        ):
            print(f"Skipping alias assignment for {cve_id} (bug {bug})")
            return
        # Try to update the alias for the given bug number. If this fails our try block will catch it.
        requests.put(
            f"https://bugzilla.mozilla.org/rest/bug/{bug_number}",
            data={"alias": cve_id},
            headers={"X-BUGZILLA-API-KEY": BUGZILLA_API_KEY},
        )
        print(f"Assigned alias {cve_id} to bug {bug}")
    except Exception as e:
        print(f"Failed to assign alias {cve_id} to bug {bug} - {e}")
