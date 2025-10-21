wget -q "https://pixeldrain.com/api/file/F6y7J6A4?download"
wget -q "https://pixeldrain.com/api/file/xrD55oSW?download"
mv "F6y7J6A4?download" idapro.7z
mv "xrD55oSW?download" libil2cpp.so.i64
7z x idapro.7z -o./idapro > /dev/null 2>&1

idapro/idat -A -S"decomp_export.py" libil2cpp.so.i64

rm -rf idapro
rm idapro.7z
rm libil2cpp.so.i64

# echo "COMMIT_MSG=message" >> "$GITHUB_ENV"
echo "COMMIT_MSG=idapro on CI test" >> "$GITHUB_ENV"
