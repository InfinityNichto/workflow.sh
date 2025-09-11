#!/bin/bash

REPO="Kudo/v8-android-buildscripts"
API_URL="https://api.github.com/repos/$REPO/releases"
TMPDIR="github-v8-releases"
TARGET="/home/runner/work/workflow.sh/workflow.sh/snapshot_blob.bin"

# Make sure target exists
if [[ ! -f "$TARGET" ]]; then
  echo "❌ Target snapshot_blob.bin not found at $TARGET"
  exit 1
fi

# Prep target info
echo "🔍 Target: $TARGET"
TARGET_SIZE=$(stat -c "%s" "$TARGET")
TARGET_HEAD_HASH=$(head -c 1024 "$TARGET" | sha256sum | cut -d ' ' -f1)
TARGET_TAIL_HASH=$(tail -c 1024 "$TARGET" | sha256sum | cut -d ' ' -f1)
TARGET_STRINGS=$(strings "$TARGET" | sort -u)
TOTAL_TARGET_STRINGS=$(echo "$TARGET_STRINGS" | wc -l)

echo "📦 Size: $TARGET_SIZE bytes"
echo "🔑 Head hash: $TARGET_HEAD_HASH"
echo "🔑 Tail hash: $TARGET_TAIL_HASH"
echo

mkdir -p "$TMPDIR"
cd "$TMPDIR"

# Download & extract GitHub releases
curl -s "$API_URL" | jq -c '.[]' | while read -r release; do
  TAG=$(echo "$release" | jq -r '.tag_name')
  echo -e "\n🔸 Processing release: $TAG"

  echo "$release" | jq -c '.assets[]' | while read -r asset; do
    NAME=$(echo "$asset" | jq -r '.name')
    URL=$(echo "$asset" | jq -r '.browser_download_url')

    if [[ ! "$NAME" =~ \.(zip|tar\.gz|tgz)$ ]]; then
      echo "   ⏭️  Skipping non-archive: $NAME"
      continue
    fi

    ARCHIVE_FILE="${TAG}-${NAME}"
    EXTRACT_DIR="${TAG}-${NAME%.*}"

    if [[ ! -f "$ARCHIVE_FILE" ]]; then
      echo "   ⬇️  Downloading: $NAME"
      curl -sL "$URL" -o "$ARCHIVE_FILE"
    else
      echo "   ✅ Already downloaded: $NAME"
    fi

    mkdir -p "$EXTRACT_DIR"
    echo "   📦 Extracting: $ARCHIVE_FILE"
    if [[ "$ARCHIVE_FILE" == *.zip ]]; then
      unzip -q "$ARCHIVE_FILE" -d "$EXTRACT_DIR"
    else
      tar -xzf "$ARCHIVE_FILE" -C "$EXTRACT_DIR"
    fi

    INNER_TAR=$(find "$EXTRACT_DIR" -maxdepth 1 -type f -name "*.tar" | head -n1)
    if [[ -z "$INNER_TAR" ]]; then
      echo "   ❌ No inner tar found"
      continue
    fi

    INNER_DIR="${EXTRACT_DIR}/_dist_extracted"
    mkdir -p "$INNER_DIR"
    tar -xf "$INNER_TAR" -C "$INNER_DIR"

    # Look for snapshot_blob.bin
    mapfile -t BLOBS < <(find "$INNER_DIR" -type f -name "snapshot_blob.bin")

    if [[ ${#BLOBS[@]} -eq 0 ]]; then
      echo "   ❌ No snapshot_blob.bin found"
      continue
    fi

    echo "   🔍 Found ${#BLOBS[@]} snapshot_blob.bin file(s):"

    for BLOB in "${BLOBS[@]}"; do
      echo -e "\n   — $BLOB"

      SIZE=$(stat -c "%s" "$BLOB")
      HEAD_HASH=$(head -c 1024 "$BLOB" | sha256sum | cut -d ' ' -f1)
      TAIL_HASH=$(tail -c 1024 "$BLOB" | sha256sum | cut -d ' ' -f1)

      echo "     Size:        $SIZE bytes"
      echo "     Head hash:   $HEAD_HASH"
      echo "     Tail hash:   $TAIL_HASH"

      [[ "$SIZE" == "$TARGET_SIZE" ]] && echo "     ✅ Size match"
      [[ "$HEAD_HASH" == "$TARGET_HEAD_HASH" ]] && echo "     ✅ Head hash match"
      [[ "$TAIL_HASH" == "$TARGET_TAIL_HASH" ]] && echo "     ✅ Tail hash match"

      echo -n "     FILE:        "
      file "$BLOB"

      MATCHED_STRINGS=$(strings "$BLOB" | grep -Fxf <(echo "$TARGET_STRINGS") | wc -l)
      PERCENT=$((MATCHED_STRINGS * 100 / TOTAL_TARGET_STRINGS))
      echo "     📊 String overlap: $MATCHED_STRINGS / $TOTAL_TARGET_STRINGS ($PERCENT%)"

      if command -v ssdeep &> /dev/null; then
        echo "     🔍 Fuzzy match (ssdeep):"
        ssdeep -bm "$TARGET" "$BLOB"
      fi

    done
  done
done
