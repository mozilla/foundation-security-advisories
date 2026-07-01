#!/bin/sh
set -e
pip install -e .
hooks_dir="$(git rev-parse --git-path hooks)"
ln -sf ../../pre-commit-hook.sh "$hooks_dir/pre-commit"
echo "Installed pre-commit hook -> pre-commit-hook.sh"

if [ ! -f .env ]; then
    cp .env.template .env
    echo ""
    echo "Created .env from template. Please edit it and fill in your credentials!"
else
    echo ".env already exists, not copying .env.template."
fi
