git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
export PATH="$PATH:$(pwd)/depot_tools"
fetch v8
cd v8
tools/dev/v8gen.py x64.release
ninja -C out.gn/x64.release v8_monolith

echo "COMMIT_MSG=build v8" >> "$GITHUB_ENV"
