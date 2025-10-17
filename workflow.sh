git clone https://github.com/TinyCC/tinycc
cd tinycc
rm -rf .git

sudo apt install build-essential

make clean
./configure
make
