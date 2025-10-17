if [ ! -e "android-ndk-r23c-linux.zip" ]; then
  wget https://dl.google.com/android/repository/android-ndk-r23c-linux.zip
  unzip android-ndk-r23c-linux -d ndk
fi

export CC="./ndk/android-ndk-r23c/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang"
export AR="./ndk/android-ndk-r23c/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"

if [ -e "tinycc" ]; then
  rm -rf tinycc
  git rm --cached tinycc
fi

git clone https://github.com/TinyCC/tinycc
cd tinycc
rm -rf .git

sudo apt install build-essential

make clean
./configure --cc=$CC --ar=$AR --cpu=arm64 --extra-cflags="-fPIC"
make

# sudo apt install tree
# tree ndk/android-ndk-r23c

# here to prevent triggering max push limit (100MB)
rm -rf ndk android-ndk-r23c-linux.zip # too lazy to add untrack feature, just delete the entire thing before automatic track
