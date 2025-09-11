#!/bin/bash

set -euo pipefail

REPO="Kudo/v8-android-buildscripts"
API_URL="https://api.github.com/repos/$REPO/releases"
TMPDIR="github-v8-releases"
LOGFILE="../v8android_so_hashes.csv"

mkdir -p "$TMPDIR"
cd "$TMPDIR"

echo "tag_name,asset_name,so_path,sha256_hash,extracted_version" > "$LOGFILE"

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

    # Find all .so files
    mapfile -t SO_FILES < <(find "$EXTRACT_DIR" -type f -name "*.so")

    if [[ ${#SO_FILES[@]} -eq 0 ]]; then
      echo "   ❌ No .so files found in $ASSET_NAME"
      continue
    fi

    for so_file in "${SO_FILES[@]}"; do
      HASH=$(sha256sum "$so_file" | awk '{print $1}')
      VERSION=$(strings "$so_file" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?' | sort -u | head -n 1)

      echo "   🔹 Found: $so_file"
      echo "      SHA256 : $HASH"
      echo "      Version: $VERSION"

      # Save to CSV log
      echo "$TAG_NAME,$ASSET_NAME,$so_file,$HASH,$VERSION" >> "$LOGFILE"
    done

  done
done
