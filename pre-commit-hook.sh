#!/bin/sh

check_advisories --staged-only

if [ "$?" -ne "0" ]; then
    echo "Aborting commit.  Fix above errors or do 'git commit --no-verify'."
    exit 1
fi

if command -v assign_cve_prompt >/dev/null 2>&1; then
    assign_cve_prompt
fi
