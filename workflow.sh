#!/bin/bash

set -euo pipefail

REPO="Kudo/v8-android-buildscripts"
API_URL="https://api.github.com/repos/$REPO/releases"
TMPDIR="github-v8-releases"

mkdir -p "$TMPDIR"
cd "$TMPDIR"

# Fetch release data
curl -s "$API_URL" | jq -c '.[]' | while read -r release; do
  TAG_NAME=$(echo "$release" | jq -r '.tag_name')
  echo -e "\n🔸 Release: $TAG_NAME"

  echo "$release" | jq -c '.assets[]' | while read -r asset; do
    ASSET_NAME=$(echo "$asset" | jq -r '.name')
    DOWNLOAD_URL=$(echo "$asset" | jq -r '.browser_download_url')

    # Skip non-archives
    if [[ ! "$ASSET_NAME" =~ \.(zip|tar\.gz|tgz)$ ]]; then
      echo "   ⏭️  Skipping: $ASSET_NAME"
      continue
    fi

    ARCHIVE_FILE="${TAG_NAME}-${ASSET_NAME}"
    EXTRACT_DIR="${TAG_NAME}-${ASSET_NAME%.*}"

    # Download if needed
    if [[ ! -f "$ARCHIVE_FILE" ]]; then
      echo "   ⬇️  Downloading: $ASSET_NAME"
      curl -sL "$DOWNLOAD_URL" -o "$ARCHIVE_FILE"
    else
      echo "   ✅ Already downloaded: $ASSET_NAME"
    fi

    # Extract top-level archive
    mkdir -p "$EXTRACT_DIR"
    echo "   📦 Extracting: $ARCHIVE_FILE"
    if [[ "$ARCHIVE_FILE" == *.zip ]]; then
      unzip -q "$ARCHIVE_FILE" -d "$EXTRACT_DIR"
    else
      tar -xzf "$ARCHIVE_FILE" -C "$EXTRACT_DIR"
    fi

    # Look for inner tar (e.g., dist.tar)
    INNER_ARCHIVE=$(find "$EXTRACT_DIR" -maxdepth 1 -type f -name "*.tar" | head -n1)
    if [[ -z "$INNER_ARCHIVE" ]]; then
      echo "   ❌ No inner .tar file found"
      continue
    fi

    INNER_DIR="${EXTRACT_DIR}/_dist_extracted"
    mkdir -p "$INNER_DIR"
    echo "   📦 Extracting inner archive: $(basename "$INNER_ARCHIVE")"
    tar -xf "$INNER_ARCHIVE" -C "$INNER_DIR"

    # Find all snapshot_blob.bin files
    mapfile -t SNAPSHOT_FILES < <(find "$INNER_DIR" -type f -name "snapshot_blob.bin")

    if [[ ${#SNAPSHOT_FILES[@]} -eq 0 ]]; then
      echo "   ❌ No snapshot_blob.bin files found"
      continue
    fi

    echo "   🔍 Found ${#SNAPSHOT_FILES[@]} snapshot_blob.bin file(s):"
    for blob in "${SNAPSHOT_FILES[@]}"; do
      echo -e "\n   — $blob"
      echo -n "     SHA256: "
      sha256sum "$blob" | awk '{print $1}'
      echo -n "     FILE:   "
      file "$blob"
    done

  done
done
