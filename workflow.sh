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
  echo -e "\n🔸 Release: $TAG_NAME"

  echo "$release" | jq -c '.assets[]' | while read -r asset; do
    ASSET_NAME=$(echo "$asset" | jq -r '.name')
    DOWNLOAD_URL=$(echo "$asset" | jq -r '.browser_download_url')

    # Skip non-archives
    if [[ ! "$ASSET_NAME" =~ \.(zip|tar\.gz|tgz)$ ]]; then
      echo "   ⏭️  Skipping non-archive: $ASSET_NAME"
      continue
    fi

    ARCHIVE_FILE="${TAG_NAME}-${ASSET_NAME}"
    EXTRACT_DIR="${TAG_NAME}-${ASSET_NAME%.*}"

    # Download if needed
    if [[ -f "$ARCHIVE_FILE" ]]; then
      echo "   ✅ Already downloaded: $ASSET_NAME"
    else
      echo "   ⬇️  Downloading: $ASSET_NAME"
      curl -sL "$DOWNLOAD_URL" -o "$ARCHIVE_FILE"
    fi

    # Extract archive
    echo "   📦 Extracting archive to: $EXTRACT_DIR"
    mkdir -p "$EXTRACT_DIR"

    if [[ "$ARCHIVE_FILE" == *.zip ]]; then
      unzip -q "$ARCHIVE_FILE" -d "$EXTRACT_DIR"
    elif [[ "$ARCHIVE_FILE" == *.tar.gz || "$ARCHIVE_FILE" == *.tgz ]]; then
      tar -xzf "$ARCHIVE_FILE" -C "$EXTRACT_DIR"
    fi

    # Find inner archive (dist.tar or similar)
    INNER_ARCHIVE=$(find "$EXTRACT_DIR" -maxdepth 1 -type f -name "*.tar" | head -n1)
    if [[ -z "$INNER_ARCHIVE" ]]; then
      echo "   ❌ No inner .tar found in $ASSET_NAME"
      continue
    fi

    INNER_DIR="${EXTRACT_DIR}/_dist_extracted"
    mkdir -p "$INNER_DIR"
    echo "   📦 Extracting inner tar: $(basename "$INNER_ARCHIVE")"
    tar -xf "$INNER_ARCHIVE" -C "$INNER_DIR"

    # Show directory structure
    echo "   📂 Tree of inner contents:"
    if command -v tree &> /dev/null; then
      tree -a -L 6 "$INNER_DIR"
    else
      find "$INNER_DIR"
    fi

    # Find all .so files
    mapfile -t SO_FILES < <(find "$INNER_DIR" -type f -name "*.so")

    if [[ ${#SO_FILES[@]} -eq 0 ]]; then
      echo "   ❌ No .so files found."
      continue
    fi

    echo "   🔍 Found ${#SO_FILES[@]} .so file(s):"
    for so_file in "${SO_FILES[@]}"; do
      echo -e "\n   — $so_file"
      echo -n "     SHA256: "
      sha256sum "$so_file" | awk '{print $1}'

      echo -n "     FILE:   "
      file "$so_file"

      VERSION=$(strings "$so_file" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?' | sort -u | head -n1)
      if [[ -n "$VERSION" ]]; then
        echo "     VERSION: $VERSION"
      else
        echo "     VERSION: not found"
      fi
    done

  done
done
