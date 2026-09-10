#!/usr/bin/env sh
# Add (or correct) the `upstream` remote pointing at the open-source project.
#
# A git remote is local configuration, so a fresh clone of the fork has no idea
# upstream exists. Every maintainer runs this once; the upstream-sync workflow
# runs the equivalent on every scheduled fetch. Idempotent by design — safe to
# run from a bootstrap script.
set -eu

UPSTREAM_URL="https://github.com/Vigil-SOC/vigil"

if git remote get-url upstream >/dev/null 2>&1; then
    current="$(git remote get-url upstream)"
    if [ "$current" = "$UPSTREAM_URL" ]; then
        echo "upstream already configured: $current"
    else
        echo "upstream pointed at $current; correcting to $UPSTREAM_URL"
        git remote set-url upstream "$UPSTREAM_URL"
    fi
else
    git remote add upstream "$UPSTREAM_URL"
    echo "added upstream: $UPSTREAM_URL"
fi

# Never push to upstream by accident.
git remote set-url --push upstream DISABLED-push-to-origin-instead

echo "fetching upstream..."
git fetch upstream --prune
echo "done. See docs/UPSTREAM.md for the sync procedure."
