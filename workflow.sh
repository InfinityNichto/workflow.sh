# Download the Unity tarball for Linux
wget https://download.unity3d.com/download_unity/4016570cf34f/LinuxEditorInstaller/Unity.tar.xz

# Extract only il2cpp
tar -xf Unity.tar.xz --wildcards "*/il2cpp/*" --strip-components=1
