#!/bin/bash

set -euo pipefail

REPO="Kudo/v8-android-buildscripts"
API_URL="https://api.github.com/repos/$REPO/releases"
TMPDIR="github-v8-releases"
LOGFILE="../v8android_tree_output.txt"

mkdir -p "$TMPDIR"
cd "$TMPDIR"

echo "📁 Tree output for each release asset:" > "$LOGFILE"

# Fetch release data from GitHub API
curl -s "$API_URL" | jq -c '.[]' | while read -r release; do
  TAG_NAME=$(echo "$release" | jq -r '.tag_name')
  echo "🔸 Processing release: $TAG_NAME"

  echo "$release" | jq -c '.assets[]' | while read -r asset; do
    ASSET_NAME=$(echo "$asset" | jq -r '.name')
    DOWNLOAD_URL=$(echo "$asset" | jq -r '.browser_download_url')

    # Only download archives
    if [[ ! "$ASSET_NAME" =~ \.(zip|tar\.gz|tgz)$ ]]; then
      echo "   ⏭️  Skipping non-archive asset: $ASSET_NAME"
      continue
    fi

    ARCHIVE_FILE="${TAG_NAME}-${ASSET_NAME}"
    EXTRACT_DIR="${TAG_NAME}-${ASSET_NAME%.*}"

    if [[ -f "$ARCHIVE_FILE" ]]; then
      echo "   ✅ Already downloaded: $ARCHIVE_FILE"
    else
      echo "   ⬇️  Downloading $ASSET_NAME..."
      curl -sL "$DOWNLOAD_URL" -o "$ARCHIVE_FILE"
    fi

    # Extract archive
    mkdir -p "$EXTRACT_DIR"
    echo "   📦 Extracting to $EXTRACT_DIR..."

    if [[ "$ARCHIVE_FILE" == *.zip ]]; then
      unzip -q "$ARCHIVE_FILE" -d "$EXTRACT_DIR"
    elif [[ "$ARCHIVE_FILE" == *.tar.gz || "$ARCHIVE_FILE" == *.tgz ]]; then
      tar -xzf "$ARCHIVE_FILE" -C "$EXTRACT_DIR"
    fi

    echo -e "\n==============================" >> "$LOGFILE"
    echo "🔍 Tree for $TAG_NAME / $ASSET_NAME" >> "$LOGFILE"
    echo "==============================" >> "$LOGFILE"

    if command -v tree &> /dev/null; then
      tree -a -L 5 "$EXTRACT_DIR" >> "$LOGFILE"
    else
      echo "⚠️ 'tree' command not found. Please install it to view archive contents." >> "$LOGFILE"
    fi

  done
done
