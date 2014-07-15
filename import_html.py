#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
Import security advisories and known-vulnerabilities from
old HTML/PHP files and convert to snippets of Markdown.
"""
from __future__ import unicode_literals

import argparse
import re
import sys
from cgi import escape
from xml.etree import ElementTree as etree

from pathlib import Path
from pyquery import PyQuery as pq


BASE_PATH = Path(__file__).resolve().parent
TITLE_RE = re.compile('\$html_title = [\'"](.*)[\'"];')
DIE_PHP = re.compile(r'<\?.*?\?>', re.DOTALL)
MFSA_ID_RE = re.compile(r'\d{4}-\d{2,4}')

config = {}


def die_php_die(file_path):
    """Return the title and file contents with any PHP sections removed."""
    with file_path.open() as fh:
        # strip php
        contents = fh.read()

    m = TITLE_RE.search(contents)
    return m.group(1), DIE_PHP.sub('', contents)


def extract_metadata(doc):
    """Extract metadata from the HTML, remove said HTML, and return remaining content and data."""
    metadata = {}
    curr_key = None
    p = doc('p').eq(0)
    for el in p.contents():
        # have to inspect due to _ElementStringResult objects
        if curr_key and not hasattr(el, 'tag'):
            text = escape(unicode(el.strip()))
            # remove newlines and multiple whitespace.
            text = re.sub(r'\s+', ' ', text, flags=re.MULTILINE)
            if text:
                metadata[curr_key][-1] += text
        elif hasattr(el, 'tag'):
            if el.tag == 'span':
                key = slugify(unicode(el.text))
                if key and not key.startswith('&'):
                    metadata[key] = ['']
                    curr_key = key
                else:
                    metadata[curr_key].append('')
            elif el.tag in ['br', 'p']:
                continue
            else:
                # add space if not beginning of string
                if metadata[curr_key][-1]:
                    metadata[curr_key][-1] += ' '
                metadata[curr_key][-1] += etree.tostring(el)

    if doc.eq(0).is_('h1'):
        doc = pq(doc[2:])
    else:
        doc = pq(doc[1:])
    return metadata, doc


def slugify(value):
    """Turn metadata keys into useful identifiers."""
    value = re.sub('[^\w\s_]', '', value).strip().lower()
    return re.sub('[_\s]+', '_', value)


def format_metadata(metadata):
    lines = []
    for k in sorted(metadata.keys()):
        v = metadata[k]
        if v:
            lines.append('{}: {}'.format(k, v.pop()))
            for extra in v:
                lines.append('{0:>{width}}'.format(extra, width=max(len(k), 4) + 2 + len(extra)))
        else:
            lines.append(k)
    return '\n'.join(lines)


def write_file(in_file_path, metadata, contents):
    out_file_path = config['output_path'] / in_file_path.relative_to(config['input_path'])
    out_file_path = out_file_path.with_suffix('.md')
    try:
        out_file_path.parent.mkdir(parents=True)
    except OSError:
        pass
    with out_file_path.open('w') as fh:
        fh.write('\n\n'.join([format_metadata(metadata), contents]))
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

        metadata, doc = extract_metadata(doc)
        metadata['page_title'] = [title]
        metadata['mfsa_id'] = [MFSA_ID_RE.search(title).group(0)]
        write_file(announcement, metadata, unicode(doc))
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
