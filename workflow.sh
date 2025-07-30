cd Iosevka/Iosevka-main
sudo apt install npm ttfautohint
npm install
npm run build -- ttf::PurificationQuasiPropo
mkdir ../../output
mv -v dist/* ../../output
