#!/bin/bash

set -euo pipefail

REPO="Kudo/v8-android-buildscripts"
API_URL="https://api.github.com/repos/$REPO/releases"
TMPDIR="github-v8-releases"

mkdir -p "$TMPDIR"
cd "$TMPDIR"

# Get all releases
curl -s "$API_URL" | jq -c '.[]' | while read -r release; do
  TAG_NAME=$(echo "$release" | jq -r '.tag_name')
  echo "🔸 Release: $TAG_NAME"

  echo "$release" | jq -c '.assets[]' | while read -r asset; do
    ASSET_NAME=$(echo "$asset" | jq -r '.name')
    DOWNLOAD_URL=$(echo "$asset" | jq -r '.browser_download_url')

    # Skip non-archive assets
    if [[ ! "$ASSET_NAME" =~ \.(zip|tar\.gz|tgz)$ ]]; then
      echo "   ⏭️  Skipping: $ASSET_NAME (not an archive)"
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

    if [[ "$ARCHIVE_FILE" == *.zip ]]; then
      unzip -q "$ARCHIVE_FILE" -d "$EXTRACT_DIR"
    elif [[ "$ARCHIVE_FILE" == *.tar.gz || "$ARCHIVE_FILE" == *.tgz ]]; then
      tar -xzf "$ARCHIVE_FILE" -C "$EXTRACT_DIR"
    fi

    echo "   📂 Directory structure:"
    if command -v tree &> /dev/null; then
      tree -a -L 5 "$EXTRACT_DIR"
    else
      echo "   ⚠️ 'tree' not installed"
      find "$EXTRACT_DIR"
    fi

    echo ""
  done
done
