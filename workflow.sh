#!/bin/bash

PACKAGE="v8-android"
VERSIONS=$(npm view $PACKAGE versions --json | jq -r '.[]')

for version in $VERSIONS; do
  echo "Installing: $PACKAGE@$version"
  DIR="${PACKAGE}-${version}"
  mkdir "$DIR"
  cd "$DIR"
  
  npm init -y > /dev/null 2>&1
  npm install "${PACKAGE}@${version}" > /dev/null 2>&1

  echo "Searching for .so files in $PACKAGE@$version..."

  # Find all .so files named libv8android.so
  mapfile -t SO_FILES < <(find node_modules/$PACKAGE -type f -name "libv8android.so")

  if [[ ${#SO_FILES[@]} -eq 0 ]]; then
    echo "❌ No libv8android.so found in $PACKAGE@$version"
    cd ..
    continue
  fi

  for so_file in "${SO_FILES[@]}"; do
    HASH=$(sha256sum "$so_file" | awk '{print $1}')
    VERSION_STRING=$(strings "$so_file" | grep -Eo "[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?" | sort -u)

    echo "🔹 Found: $so_file"
    echo "    SHA256 : $HASH"
    echo "    Version: $VERSION_STRING"
  done

  cd ..
done
