#!/bin/sh

python check_advisories.py --staged

if [ "$?" -ne "0" ]; then
    echo "Aborting commit.  Fix above errors or do 'git commit --no-verify'."
    exit 1
fi
