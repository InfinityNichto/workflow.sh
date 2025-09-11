#!/bin/bash

REPO="Kudo/v8-android-buildscripts"
API_URL="https://api.github.com/repos/$REPO/releases"
TMPDIR="github-v8-releases"
mkdir -p "$TMPDIR"
cd "$TMPDIR"

# Fetch releases list (use GitHub token if rate-limited)
curl -s "$API_URL" | jq -c '.[]' | while read -r release; do
  TAG_NAME=$(echo "$release" | jq -r '.tag_name')
  echo "Fetching release: $TAG_NAME"

  ASSETS=$(echo "$release" | jq -c '.assets[]')

  for asset in $ASSETS; do
    ASSET_NAME=$(echo "$asset" | jq -r '.name')
    DOWNLOAD_URL=$(echo "$asset" | jq -r '.browser_download_url')

    # Skip non-archive files
    if [[ ! "$ASSET_NAME" =~ \.(zip|tar\.gz|tgz)$ ]]; then
      echo "Skipping non-archive asset: $ASSET_NAME"
      continue
    fi

    ASSET_FILE="$TAG_NAME-$ASSET_NAME"
    if [[ -f "$ASSET_FILE" ]]; then
      echo "Already downloaded: $ASSET_FILE"
    else
      echo "Downloading $ASSET_NAME..."
      curl -sL "$DOWNLOAD_URL" -o "$ASSET_FILE"
    fi

    EXTRACT_DIR="${TAG_NAME}-${ASSET_NAME%.*}"
    mkdir -p "$EXTRACT_DIR"

    # Extract
    if [[ "$ASSET_NAME" == *.zip ]]; then
      unzip -q "$ASSET_FILE" -d "$EXTRACT_DIR"
    elif [[ "$ASSET_NAME" == *.tar.gz || "$ASSET_NAME" == *.tgz ]]; then
      tar -xzf "$ASSET_FILE" -C "$EXTRACT_DIR"
    fi

    # Search for .so files
    mapfile -t SO_FILES < <(find "$EXTRACT_DIR" -type f -name "libv8android.so")

    if [[ ${#SO_FILES[@]} -eq 0 ]]; then
      echo "❌ No libv8android.so in $ASSET_NAME"
    else
      for so_file in "${SO_FILES[@]}"; do
        HASH=$(sha256sum "$so_file" | awk '{print $1}')
        VERSION=$(strings "$so_file" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?' | sort -u | head -n 1)
        echo "🔹 Found in $ASSET_NAME:"
        echo "    Path   : $so_file"
        echo "    SHA256 : $HASH"
        echo "    Version: $VERSION"
      done
    fi

  done
done
