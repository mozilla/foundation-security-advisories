#!/usr/bin/env python3

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
Parse markdown files and verify syntax of YAML front-matter. Designed for use as a
git pre-commit hook.
"""
from __future__ import unicode_literals, print_function

import argparse
import re
import sys
from datetime import date

from dateutil.parser import parse as parsedate
from schema import Schema, Regex, Optional, Or, SchemaError

from foundation_security_advisories.common import (
    HOF_FILENAME_RE,
    parse_md_file,
    parse_yml_file,
    get_all_files,
    get_modified_files
)

CVE_RE = re.compile('^(CVE|MFSA-TMP|MFSA-RESERVE)-20[0-9]{2}-[0-9]{4,9}$')
md_schema = Schema({
    'mfsa_id': str,
    'fixed_in': [str],
    'title': str,
    Optional('announced'): str,
    Optional('impact'): str,
    Optional('reporter'): str,
    Optional('risk'): str,
    Optional('vulnerable'): [str],
})
yaml_schema = Schema({
    'mfsa_id': str,
    'fixed_in': [str],
    'title': str,
    'impact': str,
    'advisories': {
        Regex(CVE_RE): {
            'title': Or(str, type(None)),
            'impact': str,
            'reporter': Or(str, type(None)),
            'description': str,
            'bugs': [{'url': Or(str, int),
                      Optional('desc'): Or(str, type(None), int)}],
            Optional('feed'): bool,
        },
    },
    Optional('announced'): str,
    Optional('description'): str,
    Optional('feed'): bool,
})


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
        schema = md_schema
    elif file_name.endswith('.yml'):
        parser = parse_yml_file
        schema = yaml_schema
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

    for f in data['fixed_in']:
        if "ESR" in f and "ESR " not in f:
            return "When ESR is specified, it must be of the form 'Firefox ESR XX', not 'Firefox ESRXX' (Found '" + f + "')"
        if "," in f:
            return f"When 'fixed_in' contains multiple products, they should be enumerated with YAML and not with commas in a string (Found '{f}')"

    if 'announced' in data:
        try:
            parsedate(data['announced']).date()
        except Exception:
            return 'Failed to parse "{}" as a date'.format(data['announced'])

    try:
        schema.validate(data)
    except SchemaError as e:
        return str(e)

    return None


def main():
    parser = argparse.ArgumentParser(description='Check the syntax of advisory files.')
    parser.add_argument('--all', action='store_true',
                        help='Check all advisories regardless of git.')
    parser.add_argument('--staged-only', dest='staged', action='store_true',
                        help='Check only files staged in git (good for git hook).')
    args = parser.parse_args()

    if args.all:
        print('Checking all files')
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
        print()
    print('Checked {0} file{1}. Found {2} error{3}.'.format(num_files, files_plural,
                                                            num_errors, errors_plural))

    if errors:
        print('\nERRORS:')
        for error_tuple in errors:
            print('  - {0}: {1}'.format(*error_tuple))
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
