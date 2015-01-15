#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
Import security advisories from old HTML/PHP files
and convert to snippets of Markdown.
"""
from __future__ import unicode_literals

import argparse
import re
import sys
from cgi import escape
from xml.etree import ElementTree as etree

from pathlib import Path
from pyquery import PyQuery as pq
from yaml import safe_dump


BASE_PATH = Path(__file__).resolve().parent
TITLE_RE = re.compile('\$html_title = [\'"]MFSA (\d{4}-\d{2,4}):?\s+(.*?)[\'"];', flags=re.DOTALL)
DIE_PHP = re.compile(r'<\?.*?\?>', re.DOTALL)
META_KEY_MAP = {
    'date': 'announced',
    'severity': 'impact',
}
ALL_DATES = {}

config = {}


def die_php_die(file_path):
    """Return the title and file contents with any PHP sections removed."""
    with file_path.open() as fh:
        # strip php
        contents = fh.read()

    m = TITLE_RE.search(contents)
    return m.group(1), m.group(2), DIE_PHP.sub('', contents)


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
                key = el.text
                if key:
                    key = slugify(unicode(key))
                if key and not key == curr_key and not key.startswith('&'):
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

    # we'll use "fixed_in" for products lists.
    try:
        del metadata['products']
    except KeyError:
        pass
    try:
        del metadata['product']
    except KeyError:
        pass

    # reduce all but specific keys to single entries
    for k, v in metadata.iteritems():
        if k != 'fixed_in' and len(v) == 1:
            metadata[k] = v[0]

    new_fixed_in = []
    for product in metadata['fixed_in']:
        if ',' in product:
            product_list = [prod.strip() for prod in product.split(',')]
        else:
            product_list = [product]

        new_fixed_in.extend(product_list)

    metadata['fixed_in'] = new_fixed_in

    # fix some keys
    for old_key, new_key in META_KEY_MAP.items():
        if old_key in metadata:
            metadata[new_key] = metadata.pop(old_key)

    return metadata, pq(doc[doc.index(doc('p')[0]) + 1:])


def slugify(value):
    """Turn metadata keys into useful identifiers."""
    value = re.sub('[^\w\s_]', '', value).strip().lower()
    return re.sub('[_\s]+', '_', value)


def format_metadata(metadata):
    yaml = safe_dump(metadata, default_flow_style=False)
    return '---\n{0}---'.format(yaml)


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


def get_all_announce_dates():
    date_re = re.compile('<h3>(.*)</h3>', flags=re.IGNORECASE)
    id_re = re.compile('MFSA\s+([0-9-]+)')
    file_path = config['input_path'] / 'announce' / 'index.html'
    current_date = None
    with file_path.open() as fh:
        for line in fh:
            match = date_re.search(line)
            if match:
                current_date = match.group(1).strip()
                continue

            match = id_re.search(line)
            if match:
                ALL_DATES[match.group(1)] = current_date


def process_announce():
    announce_path = config['input_path'] / 'announce'
    counter = 0
    for announcement in announce_path.glob('*/mfsa*.html'):
        mfsa_id, title, html = die_php_die(announcement)
        title = title.replace(r"\'", "'")
        doc = pq(html)
        if doc('#main-content'):
            # it's the old style
            doc = pq(doc('#main-content').children()[2:])
        else:
            # it's the new style
            doc = pq(doc.children()[2:])

        metadata, doc = extract_metadata(doc)
        if 'title' not in metadata:
            metadata['title'] = title
        if 'announced' not in metadata:
            metadata['announced'] = ALL_DATES[mfsa_id]
        write_file(announcement, metadata, unicode(doc))
        counter += 1

    print '\nWrote {} MFSAs.'.format(counter)


def main():
    parser = argparse.ArgumentParser(description='Import and convert security HTML')
    parser.add_argument('dir', metavar='DIR',
                        help='Path to "security" directory from mozilla.org SVN.')
    parser.add_argument('-o', metavar='OUT', default=str(BASE_PATH),
                        help='Output directory (default: script dir)')
    args = parser.parse_args()
    config['input_path'] = Path(args.dir).resolve()
    config['output_path'] = Path(args.o)
    try:
        config['output_path'].mkdir(parents=True)
    except OSError:
        pass

    get_all_announce_dates()

    try:
        process_announce()
    except Exception as e:
        print 'ERROR: {}'.format(e)
        raise
        return 1

    print 'Thanks.'
    return 0


if __name__ == '__main__':
    sys.exit(main())
