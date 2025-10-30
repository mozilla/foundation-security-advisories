#!/usr/bin/env python3

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import codecs
import fnmatch
import os
import re
from glob import glob
from subprocess import check_output
from dataclasses import dataclass, field

import yaml
from markdown import markdown

GIT = os.getenv("GIT_BIN", "git")
ADVISORIES_DIR = "announce"
HOF_DIR = "bug-bounty-hof"
MFSA_FILENAME_RE = re.compile("mfsa(\d{4}-\d{2,3})\.(md|yml)$")
HOF_FILENAME_RE = re.compile("bug-bounty-hof/\w+\.yml$")
HTML_BR_TAG_RE = re.compile(r"<br */?>")
HTML_CODE_TAG_RE = re.compile(r"</?code>")
HTML_TAG_RE = re.compile(r"<[^>]+>")
HTML_NEWLINE_RE = re.compile(r"\n")
HTML_DOUBLE_NEWLINE_RE = re.compile(r"\n\n")


def mfsa_id_from_filename(filename):
    match = MFSA_FILENAME_RE.search(filename)
    if match:
        return match.group(1)

    return None


def git_diff(staged):
    """
    Return the modified files in the repo.
    :param staged: boolean return only those changes staged in git
    :return: list modified file names.
    """
    command = [GIT, "diff", "--name-only"]
    if staged:
        command.append("--cached")

    git_out = check_output(command, universal_newlines=True).split()
    return [
        fn
        for fn in git_out
        if MFSA_FILENAME_RE.search(fn) or HOF_FILENAME_RE.search(fn)
    ]


def get_modified_files(staged_only):
    """
    Return the modified file names in the repo.
    :param staged_only: boolean include all changes or only staged.
    :return: list modified file names.
    """
    staged_files = git_diff(staged=True)
    if staged_only:
        return staged_files

    modified_files = set(staged_files)
    modified_files.update(git_diff(staged=False))
    return list(modified_files)


def get_all_files():
    """
    Return all advisory file names in the repo.

    :return: generator of file names.
    """
    for root, dirnames, filenames in os.walk(ADVISORIES_DIR):
        for filename in fnmatch.filter(filenames, "mfsa*.*"):
            yield os.path.join(root, filename)

    for filename in glob("{}/*.yml".format(HOF_DIR)):
        yield filename


def parse_md_front_matter(lines):
    """Return the YAML and MD sections.

    :param: lines iterator
    :return: str YAML, str Markdown
    """
    # fm_count: 0: init, 1: in YAML, 2: in Markdown
    fm_count = 0
    yaml_lines = []
    md_lines = []
    for line in lines:
        # first line we care about is FM start
        if fm_count < 2 and line.strip() == "---":
            fm_count += 1
            continue

        if fm_count == 1:
            yaml_lines.append(line)

        if fm_count == 2:
            md_lines.append(line)

    if fm_count < 2:
        raise ValueError("Front Matter not found.")

    return "".join(yaml_lines), "".join(md_lines)


def parse_yml_file(file_name):
    """Return the YAML data for file_name."""
    with codecs.open(file_name, encoding="utf8") as fh:
        data = yaml.safe_load(fh)

    if "mfsa_id" not in data:
        mfsa_id = mfsa_id_from_filename(file_name)
        if mfsa_id:
            data["mfsa_id"] = mfsa_id
    return data


def parse_md_file(file_name):
    """Return the YAML and MD sections for file_name."""
    with codecs.open(file_name, encoding="utf8") as fh:
        yamltext, mdtext = parse_md_front_matter(fh)

    data = yaml.safe_load(yamltext)
    if "mfsa_id" not in data:
        mfsa_id = mfsa_id_from_filename(file_name)
        if mfsa_id:
            data["mfsa_id"] = mfsa_id
    # run it through parser in case of exception
    markdown(mdtext)
    return data


def remove_newlines(content: str | None):
    """Removes markdown-style newlines. Replaces '\\n\\n' with '<br />' and '\\n' with a space ' '."""
    if not content:
        return None
    content = HTML_DOUBLE_NEWLINE_RE.sub("<br />", content)
    content = HTML_NEWLINE_RE.sub(" ", content)
    return content


def remove_html_tags(content: str | None):
    """Executes `remove_newlines` and replaces <br> tags with '\\n', <code> tags with '`' and removes all other tags."""
    if not content:
        return None
    content = remove_newlines(content)
    content = HTML_BR_TAG_RE.sub("\n", content)
    content = HTML_CODE_TAG_RE.sub("`", content)
    content = HTML_TAG_RE.sub("", content)
    return content


def comma_separated(sequence: list[str], conjunction="and"):
    """
    Returns the given string list comma separated. For example: \n
    ["a","b","c","d"] -> "a, b, c, and d" \n
    ["a","b"] -> "a and b" \n
    ["a"] -> "a"
    """
    if len(sequence) > 2:
        return f"{', '.join(sequence[:-1])}, {conjunction} {sequence[-1]}"
    elif len(sequence) == 2:
        return f"{sequence[0]} {conjunction} {sequence[-1]}"
    else:
        return sequence[0]


@dataclass
class CVEAdvisory:
    """A collection of `CVEAdvisoryInstance`s with the same CVE-ID."""

    id: str
    year: int
    instances: list["CVEAdvisoryInstance"] = field(default_factory=list)

    @property
    def newest_instance(self):
        """
        Returns the last modified instance of this CVE advisory (determined by git commit time).
        Useful for when only one of the instances is being updated with the latest information.
        """
        greatest_last_modified = 0
        newest_instance: CVEAdvisoryInstance = None
        for instance in self.instances:
            if instance.file_last_modified > greatest_last_modified:
                greatest_last_modified = instance.file_last_modified
                newest_instance = instance
        return newest_instance

    @property
    def full_description(self):
        description = self.newest_instance.description.strip()

        if not description:
            if not "title" in self.newest_instance:
                raise Exception(
                    "Advisory has neither a title nor a description")

            description = self.newest_instance.title.strip().strip('.') + "."

        return (
            description
            + " This vulnerability affects "
            + comma_separated(
                [
                    f"{instance.product} < {instance.version_fixed}"
                    for instance in self.instances
                ],
            )
            + "."
        )

    def to_json(self):
        """
        Convert advisory in yml format into
        [CVE JSON](https://cveproject.github.io/cve-schema/schema/docs/) format.
        """

        return {
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "product": instance.product,
                            "vendor": "Mozilla",
                            "versions": [
                                {
                                    "lessThan": instance.version_fixed,
                                    "status": "affected",
                                    "version": "unspecified",
                                    "versionType": "custom",
                                }
                            ],
                        }
                        for instance in self.instances
                    ],
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": remove_html_tags(self.full_description),
                            "supportingMedia": [
                                {
                                    "type": "text/html",
                                    "base64": False,
                                    "value": remove_newlines(self.full_description),
                                }
                            ],
                        }
                    ],
                    **(
                        {
                            "title": remove_html_tags(
                                self.newest_instance.title
                            )
                        }
                        if self.newest_instance.title
                        else {}
                    ),
                    "references": [
                        {
                            "url": f"https://www.mozilla.org/security/advisories/mfsa{mfsa_id}/"
                        }
                        for mfsa_id in sorted(
                            set([instance.mfsa_id for instance in self.instances])
                        )
                    ]
                    + [
                        {
                            "url": url,
                            **({"name": desc} if desc else {}),
                        }
                        for url, desc in self.newest_instance.references
                    ],
                    **(
                        {
                            "credits": [
                                {
                                    "lang": "en",
                                    "value": remove_html_tags(
                                        self.newest_instance.reporter
                                    ),
                                }
                            ],
                        }
                        if self.newest_instance.reporter
                        else {}
                    ),
                }
            },
            "dataType": "CVE_RECORD",
            "dataVersion": "5.2",
        }


@dataclass
class CVEAdvisoryInstance:
    """
    A manifestation of a CVE advisory in this repository.
    Objects of this class correspond to the entries in the
    `advisories:` section of the advisory YAML format.
    """

    parent: CVEAdvisory
    title: str
    description: str
    reporter: str | None
    references: list[(str, str | None)]
    mfsa_id: str
    product: str
    version_fixed: str
    file_name: str
    file_last_modified: int
