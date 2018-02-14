#!/usr/bin/env python

from __future__ import unicode_literals
import codecs
import os.path
import re
import sys


HOF_FILES = {
    'client': 'bedrock/security/templates/security/bug-bounty/hall-of-fame.html',
    'web': 'bedrock/security/templates/security/bug-bounty/web-hall-of-fame.html',
}
OUTPUT_DIR = 'bug-bounty-hof'
QUARTER_RE = re.compile(r'^<h4>([^<]+)</h4>$')
NAME_RE = re.compile(r'^<li>(<a href="(?P<url>[^"]+)">)?(?P<name>[^<]+)(</a>)?</li>$')
QUARTER_DATE_RE = re.compile(r'(\d).+(\d{4})')


def quarter_to_date_string(quarter):
    q_num, year = QUARTER_DATE_RE.match(quarter).groups()
    month = str((int(q_num) * 3) - 2)
    month = '0' + month if len(month) == 1 else month
    return '{}-{}-01'.format(year, month)


def extract_names(filename):
    names = []
    with codecs.open(filename, encoding='utf8') as fp:
        current_date = None
        for line in fp:
            line = line.strip()
            quarter = QUARTER_RE.match(line)
            if quarter:
                current_date = quarter_to_date_string(quarter.group(1))
                continue

            if not current_date:
                continue

            name = NAME_RE.match(line)
            if name:
                names.append([current_date, name.group('name').encode('utf8'), name.group('url')])

    return names


def get_yaml(names):
    output = ['names:\n']
    for date, name, url in names:
        output.append('- name: "%s"\n' % name.decode('utf8'))
        output.append('  date: %s\n' % date)
        if url:
            output.append('  url: "%s"\n' % url)

    return output


def write_yaml(filename, content):
    with codecs.open('%s/%s.yml' % (OUTPUT_DIR, filename), 'w', encoding='utf8') as fp:
        fp.writelines(content)


def main(args):
    if len(args) != 1:
        return 'Missing required argument: path to bedrock'

    bedrock_dir = args[0]
    for file_id, filename in HOF_FILES.items():
        filename = os.path.join(bedrock_dir, filename)
        names = extract_names(filename)
        yaml = get_yaml(names)
        write_yaml(file_id, yaml)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
