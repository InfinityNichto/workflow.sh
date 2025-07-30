rm -f *.zip
cd Iosevka/Iosevka-main
sudo apt install npm ttfautohint
npm install
npm run build -- contents::Purification
