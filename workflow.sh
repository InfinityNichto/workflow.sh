#!/bin/bash
set -e

sudo apt install yarn

git clone https://github.com/Kudo/v8-android-buildscripts
cd v8-android-buildscripts
yarn setup
yarn start

echo "COMMIT_MSG=v8 android buildscripts" >> "$GITHUB_ENV"
