#!/bin/bash

set -euo pipefail

REPO="Kudo/v8-android-buildscripts"
API_URL="https://api.github.com/repos/$REPO/releases"
TMPDIR="github-v8-releases"

mkdir -p "$TMPDIR"
cd "$TMPDIR"

# Fetch release data from GitHub API
curl -s "$API_URL" | jq -c '.[]' | while read -r release; do
  TAG_NAME=$(echo "$release" | jq -r '.tag_name')
  echo "🔸 Release: $TAG_NAME"

  echo "$release" | jq -c '.assets[]' | while read -r asset; do
    ASSET_NAME=$(echo "$asset" | jq -r '.name')
    DOWNLOAD_URL=$(echo "$asset" | jq -r '.browser_download_url')

    # Only archive files
    if [[ ! "$ASSET_NAME" =~ \.(zip|tar\.gz|tgz)$ ]]; then
      echo "   ⏭️  Skipping: $ASSET_NAME (not archive)"
      continue
    fi

    ARCHIVE_FILE="${TAG_NAME}-${ASSET_NAME}"
    EXTRACT_DIR="${TAG_NAME}-${ASSET_NAME%.*}"

    if [[ -f "$ARCHIVE_FILE" ]]; then
      echo "   ✅ Already downloaded: $ASSET_NAME"
    else
      echo "   ⬇️  Downloading: $ASSET_NAME"
      curl -sL "$DOWNLOAD_URL" -o "$ARCHIVE_FILE"
    fi

    echo "   📦 Extracting to: $EXTRACT_DIR"
    mkdir -p "$EXTRACT_DIR"

    # Extract the zip/tar file
    if [[ "$ARCHIVE_FILE" == *.zip ]]; then
      unzip -q "$ARCHIVE_FILE" -d "$EXTRACT_DIR"
    elif [[ "$ARCHIVE_FILE" == *.tar.gz || "$ARCHIVE_FILE" == *.tgz ]]; then
      tar -xzf "$ARCHIVE_FILE" -C "$EXTRACT_DIR"
    fi

    # Find and extract dist.tar if present
    DIST_TAR=$(find "$EXTRACT_DIR" -type f -name "dist.tar" | head -n 1)
    if [[ -n "$DIST_TAR" ]]; then
      DIST_DIR="${EXTRACT_DIR}/_dist"
      mkdir -p "$DIST_DIR"
      tar -xf "$DIST_TAR" -C "$DIST_DIR"
    else
      echo "   ❌ No dist.tar found in $EXTRACT_DIR"
      continue
    fi

    # Find .so files in dist directory
    echo "   🔍 Searching for .so files in dist..."
    mapfile -t SO_FILES < <(find "$DIST_DIR" -type f -name "*.so")

    if [[ ${#SO_FILES[@]} -eq 0 ]]; then
      echo "   ⚠️  No .so files found."
      continue
    fi

    for so_file in "${SO_FILES[@]}"; do
      echo ""
      echo "🔹 Found: $so_file"

      HASH=$(sha256sum "$so_file" | awk '{print $1}')
      echo "   SHA256: $HASH"

      FILE_TYPE=$(file "$so_file")
      echo "   File: $FILE_TYPE"

      VERSION=$(strings "$so_file" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?' | sort -Vu | head -n 1)
      echo "   Version (from strings): ${VERSION:-N/A}"
    done

    echo ""
  done
done
