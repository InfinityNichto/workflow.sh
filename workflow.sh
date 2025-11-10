wget -q -O assets-and-metadata.zip "https://drive.usercontent.google.com/download?id=1xkRurYw4Mq7ElELBQuzblvpkeGLkupXR&export=download&authuser=0&confirm=t&uuid=35257ead-a735-42e4-8e4a-cb2f06a3063a&at=ALWLOp4wU6nDXy5z_00KCsfx-jqA%3A1762773101937"
unzip assets-and-metadata.zip -d assets-and-metadata
mv assets-and-metadata/global-metadata.dat .
rm -rf assets-and-metadata

# echo "COMMIT_MSG=message" >> "$GITHUB_ENV"
echo "COMMIT_MSG=extract global-metadata.dat" >> "$GITHUB_ENV"
