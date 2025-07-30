rm -f *.zip
rm -rfv Purification
cd Iosevka/Iosevka-main
sudo apt install npm ttfautohint
npm install
npm run build -- ttf::PurificationMono
