wget -q "https://pixeldrain.com/api/file/F6y7J6A4?download"
mv "F6y7J6A4?download" idapro.7z
7z x idapro.7z -o./idapro

idapro/idat --help

rm -rf idapro
rm idapro.7z

# echo "COMMIT_MSG=message" >> "$GITHUB_ENV"
echo "COMMIT_MSG=idapro on CI test" >> "$GITHUB_ENV"
