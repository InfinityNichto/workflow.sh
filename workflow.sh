#!/bin/bash
set -e

rm -rf v8 depot_tools
rm ./.gclient* ./.gcs*

echo "COMMIT_MSG=remove old v8" >> "$GITHUB_ENV"
