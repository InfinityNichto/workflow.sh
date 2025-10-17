if [ ! -e "android-ndk-r23c-macos.zip" ]; then
  wget -q https://dl.google.com/android/repository/android-ndk-r23c-darwin.dmg
  hdiutil attach -mountpoint /tmp/tmpmount android-ndk-r23c-darwin.dmg
  cp -r /tmp/tmpmount/* ndk
  hdiutil detach /tmp/tmpmount
  rm android-ndk-r23c-darwin.dmg
fi

# export CC="./ndk/android-ndk-r23c/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang"
# export AR="./ndk/android-ndk-r23c/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"

export CC=$(find ./ndk/ -name "aarch64-linux-android26-clang")
export AR=$(find ./ndk/ -name "llvm-ar")

if [ -e "tinycc" ]; then
  rm -rf tinycc
  git rm --cached tinycc
fi

git clone https://github.com/TinyCC/tinycc
cd tinycc
rm -rf .git

brew install make

make clean
./configure --cc=$CC --ar=$AR --cpu=arm64 --extra-cflags="-fPIC"
make

# sudo apt install tree
# tree ndk/android-ndk-r23c

# here to prevent triggering max push limit (100MB)
rm -rf ndk # too lazy to add untrack feature, just delete the entire thing before automatic track
