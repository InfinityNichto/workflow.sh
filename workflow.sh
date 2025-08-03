cd Iosevka/Iosevka-main
sudo apt install npm ttfautohint
npm install
npm run build -- ttcize
mkdir ../../output
mv -v dist/* ../../output
tar -czvf output.tar.gz ../../output
