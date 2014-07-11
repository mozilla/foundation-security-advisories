#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
Import security advisories and known-vulnerabilities from
old HTML/PHP files and convert to snippets of Markdown.
"""

import argparse
import re
import sys

from pathlib import Path
from pyquery import PyQuery as pq


BASE_PATH = Path(__file__).resolve().parent
TITLE_RE = re.compile('\$html_title = [\'"](.*)[\'"];')
DIE_PHP = re.compile(r'<\?.*?\?>', re.DOTALL)

config = {}


def die_php_die(file_path):
    """Return the title and file contents with any PHP sections removed."""
    with file_path.open() as fh:
        # strip php
        contents = fh.read()

    m = TITLE_RE.search(contents)
    return m.group(1), DIE_PHP.sub('', contents)


def write_file(in_file_path, contents):
    out_file_path = config['output_path'] / in_file_path.relative_to(config['input_path'])
    out_file_path = out_file_path.with_suffix('.md')
    try:
        out_file_path.parent.mkdir(parents=True)
    except OSError:
        pass
    with out_file_path.open('w') as fh:
        fh.write(contents.decode('utf8'))
        sys.stdout.write('.')
        sys.stdout.flush()


def process_announce():
    announce_path = config['input_path'] / 'announce'
    counter = 0
    for announcement in announce_path.glob('*/mfsa*.html'):
        title, html = die_php_die(announcement)
        doc = pq(html)
        if doc('#main-content'):
            # it's the old style
            doc = pq(doc('#main-content').children()[2:])
        else:
            # it's the new style
            doc = pq(doc.children()[2:])

        write_file(announcement, 'title: {}\n\n{}'.format(title, doc))
        counter += 1

    print '\nWrote {} MFSAs.'.format(counter)


def process_vulnerability():
    # Not sure these can or should be automatically converted
    vuln_path = config['input_path'] / 'known-vulnerabilities'
    for vuln in vuln_path.glob('*.html'):
        print vuln


def main():
    parser = argparse.ArgumentParser(description='Import and convert security HTML')
    parser.add_argument('dir', metavar='DIR',
                        help='Path to "security" directory from mozilla.org SVN.')
    parser.add_argument('-o', metavar='OUT', default=str(BASE_PATH / 'security'),
                        help='Output directory (default: ./security)')
    args = parser.parse_args()
    config['input_path'] = Path(args.dir).resolve()
    config['output_path'] = Path(args.o)
    try:
        config['output_path'].mkdir(parents=True)
    except OSError:
        pass

    try:
        process_announce()
        # process_vulnerability()
    except Exception as e:
        print 'ERROR: {}'.format(e)
        return 1

    print 'Thanks.'
    return 0


if __name__ == '__main__':
    sys.exit(main())
