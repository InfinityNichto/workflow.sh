wget -q -O idapro.7z "https://drive.usercontent.google.com/download?id=146osHMZxQyiA64QPKdOgUCukMpe6LH9U&export=download&authuser=1&confirm=t&uuid=5fe429a2-ae23-454e-afb3-3294752f4e46&at=AKSUxGPTby3v_gEWorHFWDBq6CV6:1761034267700"
wget -q -O libil2cpp.so.i64 "https://drive.usercontent.google.com/download?id=1c2qUfK_BCQDwgZ4Q4axTFQGLOFGN9uMK&export=download&authuser=1&confirm=t&uuid=470bb2af-5fa5-4d26-96e3-0dccc3beb377&at=AKSUxGNsmriOXEGLuu8leglPSAk-:1761033921133"
7z x idapro.7z -o./idapro > /dev/null 2>&1
7z x idadot.7z -o./.idapro > /dev/null 2>&1

cp .idapro ~/.idapro

idapro/idat -A -S"decomp_export.py" libil2cpp.so.i64

# rm -rf idapro
rm idapro.7z
rm libil2cpp.so.i64

# echo "COMMIT_MSG=message" >> "$GITHUB_ENV"
echo "COMMIT_MSG=idapro on CI test" >> "$GITHUB_ENV"
