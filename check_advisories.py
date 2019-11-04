#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
Parse markdown files and verify syntax of YAML front-matter. Designed for use as a
git pre-commit hook.
"""
from __future__ import unicode_literals

import argparse
import codecs
import fnmatch
import os
import re
import sys
from datetime import date
from glob import glob
from subprocess import Popen, PIPE

import yaml
from dateutil.parser import parse as parsedate
from markdown import markdown


GIT = os.getenv('GIT_BIN', 'git')
ADVISORIES_DIR = 'announce'
HOF_DIR = 'bug-bounty-hof'
CVE_RE = re.compile('^CVE-20[0-9]{2}-[0-9]{4,9}$')
MFSA_FILENAME_RE = re.compile('mfsa(\d{4}-\d{2,3})\.(md|yml)$')
HOF_FILENAME_RE = re.compile('bug-bounty-hof/\w+\.yml$')
REQUIRED_FIELDS = (
    'fixed_in',
    'title',
)
REQUIRED_YAML_FIELDS = REQUIRED_FIELDS + (
    'advisories',
)
REQUIRED_YAML_ADVISORY_FIELDS = (
    'title',
    'impact',
    'reporter',
    'description',
)


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
    command = [GIT, 'diff', '--name-only']
    if staged:
        command.append('--cached')

    proc = Popen(command, stdout=PIPE)
    git_out = proc.communicate()[0].split()

    return [fn for fn in git_out if
            MFSA_FILENAME_RE.search(fn) or HOF_FILENAME_RE.search(fn)]


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
        for filename in fnmatch.filter(filenames, 'mfsa*.*'):
            yield os.path.join(root, filename)

    for filename in glob('{}/*.yml'.format(HOF_DIR)):
        yield filename


def check_hof_data(data):
    if 'names' not in data:
        return 'Missing required key: names'

    if len(data['names']) < 100:
        return 'Suspiciously few names returned. File may be corrupted.'

    for name in data['names']:
        if 'name' not in name:
            return 'Key "name" required for every entry in "names"'
        if 'date' not in name:
            return 'Key "date" required for every entry in "names"'
        if not isinstance(name['date'], date):
            return 'Key "date" should be formatted as a date (YYYY-MM-DD): %s' % name['date']
        if name['date'] < date(2004, 11, 9):
            return 'A date can\'t be set before the launch date of Firefox'

    return None


def check_file(file_name):
    """
    Check the given file for parse errors.
    :param file_name: file name to check
    :return: str error message.
    """
    if file_name.endswith('.md'):
        parser = parse_md_file
        required_fields = REQUIRED_FIELDS
    elif file_name.endswith('.yml'):
        parser = parse_yml_file
        required_fields = REQUIRED_YAML_FIELDS
    else:
        return 'Unknown file type: %s' % file_name

    try:
        data = parser(file_name)
    except Exception as e:
        return str(e)

    if HOF_FILENAME_RE.search(file_name):
        return check_hof_data(data)

    if 'mfsa_id' not in data:
        return 'The MFSA ID must be in the filename or metadata.'

    for field in required_fields:
        if field not in data:
            return 'The {0} field is required in the file metadata.'.format(field)

    if 'announced' in data:
        try:
            parsedate(data['announced']).date()
        except Exception:
            return 'Failed to parse "{}" as a date'.format(data['announced'])

    if file_name.endswith('.yml'):
        for cve, advisory in data['advisories'].items():
            if not CVE_RE.search(cve):
                return 'The cve field {0} does not appear to be valid.'.format(cve)
            for field in REQUIRED_YAML_ADVISORY_FIELDS:
                if field not in advisory:
                    return 'The {0} field is required in the ' \
                           'file metadata for {1}.'.format(field, cve)

    return None


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
        if fm_count < 2 and line.strip() == '---':
            fm_count += 1
            continue

        if fm_count == 1:
            yaml_lines.append(line)

        if fm_count == 2:
            md_lines.append(line)

    if fm_count < 2:
        raise ValueError('Front Matter not found.')

    return ''.join(yaml_lines), ''.join(md_lines)


def parse_yml_file(file_name):
    """Return the YAML data for file_name."""
    with codecs.open(file_name, encoding='utf8') as fh:
        data = yaml.safe_load(fh)

    if 'mfsa_id' not in data:
        mfsa_id = mfsa_id_from_filename(file_name)
        if mfsa_id:
            data['mfsa_id'] = mfsa_id
    return data


def parse_md_file(file_name):
    """Return the YAML and MD sections for file_name."""
    with codecs.open(file_name, encoding='utf8') as fh:
        yamltext, mdtext = parse_md_front_matter(fh)

    data = yaml.safe_load(yamltext)
    if 'mfsa_id' not in data:
        mfsa_id = mfsa_id_from_filename(file_name)
        if mfsa_id:
            data['mfsa_id'] = mfsa_id
    # run it through parser in case of exception
    markdown(mdtext)
    return data


def main():
    parser = argparse.ArgumentParser(description='Check the syntax of advisory files.')
    parser.add_argument('--all', action='store_true',
                        help='Check all advisories regardless of git.')
    parser.add_argument('--staged-only', dest='staged', action='store_true',
                        help='Check only files staged in git (good for git hook).')
    args = parser.parse_args()

    if args.all:
        print 'Checking all files\n'
        files_to_check = get_all_files()
    else:
        files_to_check = get_modified_files(args.staged)

    errors = []
    num_files = 0
    for file_name in files_to_check:
        num_files += 1
        error_msg = check_file(file_name)
        if error_msg:
            errors.append((file_name, error_msg))

        if args.all:
            sys.stdout.write('E' if error_msg else '.')
            sys.stdout.flush()

    files_plural = '' if num_files == 1 else 's'
    num_errors = len(errors)
    errors_plural = '' if num_errors == 1 else 's'
    if args.all:
        print
    print 'Checked {0} file{1}. Found {2} error{3}.'.format(num_files, files_plural,
                                                            num_errors, errors_plural)

    if errors:
        print '\nERRORS:'
        for error_tuple in errors:
            print '  - {0}: {1}'.format(*error_tuple)
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
