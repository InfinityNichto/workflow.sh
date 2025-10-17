if [ ! -e "android-ndk-r23c-linux.zip" ]; then
  wget https://dl.google.com/android/repository/android-ndk-r23c-linux.zip
  unzip android-ndk-r23c-linux -d ndk
  ls -la ndk
  ls -la ndk/*
fi

# if [ -e "tinycc" ]; then
#   rm -rf tinycc
#   git rm --cached tinycc
# fi

# git clone https://github.com/TinyCC/tinycc
# cd tinycc
# rm -rf .git

# sudo apt install build-essential

# make clean
# ./configure
# make
