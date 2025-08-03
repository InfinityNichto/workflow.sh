# cd Iosevka/Iosevka-main
# sudo apt install npm ttfautohint
# npm install
# npm run build -- ttf::IosevkaSs05QuasiProportional
# mv -v dist/* ../../output
# tar -czvf ../../output.tar.gz ../../output
rm output.tar.gz
tar -czvf output.tar.gz output/IosevkaSs05QuasiProportional

echo "COMMIT_MSG=compress IosevkaSs05QuasiProportional" >> "$GITHUB_ENV"
