#!/bin/bash
set -e

sudo apt install yarn
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

  # Try to locate the include directory (recursively find path)
  INCLUDE_DIR=$(find node_modules/$PACKAGE -type d -path "*/include" | head -n 1)

  if [[ -z "$INCLUDE_DIR" ]]; then
    echo "❌ Include directory not found for $PACKAGE@$version"
    cd ..
    continue
  fi

  # Compute hash of all files inside the include directory
  HASH=$(find "$INCLUDE_DIR" -type f -exec sha256sum {} + | sort | sha256sum | awk '{print $1}')

  echo "✅ $PACKAGE@$version → $HASH"
  
  cd ..
done

echo "COMMIT_MSG=libv8android hash check" >> "$GITHUB_ENV"
