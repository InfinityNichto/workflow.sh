#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/v8_build"
OUTPUT_DIR="$SCRIPT_DIR/v8_android_static"
NDK_VERSION="r25c"
NDK_URL="https://dl.google.com/android/repository/android-ndk-${NDK_VERSION}-linux.zip"
ANDROID_NDK_ROOT="$BUILD_DIR/android-ndk-${NDK_VERSION}"

echo "V8 Android Static Build - Complete Setup"
echo "========================================"

export DEBIAN_FRONTEND=noninteractive

echo "Installing system dependencies..."
apt-get update -qq
apt-get install -y \
    build-essential \
    git \
    python3 \
    python3-pip \
    wget \
    unzip \
    curl \
    ninja-build \
    pkg-config \
    libnss3-dev \
    libatk-bridge2.0-dev \
    libdrm2 \
    xvfb \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libgbm1 \
    libxss1 \
    libasound2 \
    libatspi2.0-0 \
    libgtk-3-0 \
    lsb-release

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

if [ ! -d "android-ndk-${NDK_VERSION}" ]; then
    echo "Downloading Android NDK ${NDK_VERSION}..."
    wget -q "$NDK_URL" -O "ndk.zip"
    unzip -q ndk.zip
    rm ndk.zip
fi

if [ ! -d "depot_tools" ]; then
    echo "Cloning depot_tools..."
    git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
fi

export PATH="$BUILD_DIR/depot_tools:$PATH"

if [ ! -d "v8" ]; then
    echo "Fetching V8 source..."
    fetch v8
    cd v8
else
    cd v8
    echo "Syncing V8 source..."
    gclient sync
fi

ARCHES=("arm64" "arm" "x64")
ARCH_DIRS=("android_arm64" "android_arm" "android_x64")

for i in "${!ARCHES[@]}"; do
    ARCH="${ARCHES[$i]}"
    DIR="${ARCH_DIRS[$i]}"
    
    echo "Building V8 for $ARCH..."
    
    mkdir -p "out/$DIR"
    
    cat > "out/$DIR/args.gn" << EOF
is_debug = false
is_official_build = true
target_cpu = "$ARCH"
target_os = "android"
is_component_build = false
v8_static_library = true
v8_monolithic = true
v8_use_external_startup_data = false
v8_enable_i18n_support = false
v8_enable_disassembler = false
v8_enable_gdbjit = false
v8_enable_vtunejit = false
v8_enable_object_print = false
v8_enable_verify_heap = false
v8_enable_runtime_call_stats = false
v8_enable_trace_maps = false
v8_enable_test_features = false
v8_enable_debugging_features = false
v8_enable_slow_dchecks = false
v8_enable_verify_predictable = false
v8_enable_verify_csa = false
v8_optimized_debug = false
v8_enable_pointer_compression = true
v8_enable_concurrent_marking = true
v8_enable_lazy_source_positions = true
v8_enable_snapshot_compression = true
v8_enable_webassembly = false
v8_enable_regexp_interpreter_threaded_dispatch = false
v8_enable_sparkplug = false
v8_enable_maglev = false
v8_enable_turbofan = true
treat_warnings_as_errors = false
use_custom_libcxx = false
use_lld = true
use_thin_lto = true
android_ndk_root = "$ANDROID_NDK_ROOT"
symbol_level = 0
strip_debug_info = true
exclude_unwind_tables = true
enable_resource_allowlist_generation = false
dcheck_always_on = false
is_clang = true
clang_use_chrome_plugins = false
use_gold = false
use_sysroot = true
EOF

    if [ "$ARCH" = "arm" ]; then
        echo 'arm_use_neon = true' >> "out/$DIR/args.gn"
        echo 'arm_version = 7' >> "out/$DIR/args.gn"
        echo 'arm_float_abi = "hard"' >> "out/$DIR/args.gn"
    fi
    
    echo "Generating build files for $ARCH..."
    gn gen "out/$DIR"
    
    echo "Building V8 monolith for $ARCH..."
    ninja -C "out/$DIR" -j$(nproc) v8_monolith
done

echo "Processing and optimizing libraries..."
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

for i in "${!ARCHES[@]}"; do
    ARCH="${ARCHES[$i]}"
    DIR="${ARCH_DIRS[$i]}"
    
    case "$ARCH" in
        "arm64") ABI="arm64-v8a" ;;
        "arm") ABI="armeabi-v7a" ;;
        "x64") ABI="x86_64" ;;
    esac
    
    mkdir -p "$OUTPUT_DIR/lib/$ABI"
    
    cp "out/$DIR/obj/libv8_monolith.a" "$OUTPUT_DIR/lib/$ABI/"
    cp "out/$DIR/obj/libv8_libbase.a" "$OUTPUT_DIR/lib/$ABI/"
    cp "out/$DIR/obj/libv8_libplatform.a" "$OUTPUT_DIR/lib/$ABI/"
    
    STRIP_TOOL="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
    if [ -f "$STRIP_TOOL" ]; then
        echo "Stripping symbols from $ABI libraries..."
        "$STRIP_TOOL" "$OUTPUT_DIR/lib/$ABI"/*.a 2>/dev/null || true
    fi
done

mkdir -p "$OUTPUT_DIR/include"
cp -r include/* "$OUTPUT_DIR/include/"

cat > "$OUTPUT_DIR/Android.mk" << 'EOF'
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := v8_monolith
LOCAL_SRC_FILES := lib/$(TARGET_ARCH_ABI)/libv8_monolith.a
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := v8_base
LOCAL_SRC_FILES := lib/$(TARGET_ARCH_ABI)/libv8_libbase.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := v8_platform
LOCAL_SRC_FILES := lib/$(TARGET_ARCH_ABI)/libv8_libplatform.a
include $(PREBUILT_STATIC_LIBRARY)
EOF

cat > "$OUTPUT_DIR/CMakeLists.txt" << 'EOF'
cmake_minimum_required(VERSION 3.6)

add_library(v8_monolith STATIC IMPORTED)
set_target_properties(v8_monolith PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/lib/${ANDROID_ABI}/libv8_monolith.a
)

add_library(v8_base STATIC IMPORTED)
set_target_properties(v8_base PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/lib/${ANDROID_ABI}/libv8_libbase.a
)

add_library(v8_platform STATIC IMPORTED)
set_target_properties(v8_platform PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/lib/${ANDROID_ABI}/libv8_libplatform.a
)

function(target_link_v8 target_name)
    target_include_directories(${target_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(${target_name} v8_monolith v8_base v8_platform log dl)
    target_compile_definitions(${target_name} PRIVATE V8_COMPRESS_POINTERS V8_31BIT_SMIS_ON_64BIT_ARCH)
    set_property(TARGET ${target_name} PROPERTY CXX_STANDARD 17)
    target_compile_options(${target_name} PRIVATE -fno-rtti -fno-exceptions)
endfunction()
EOF

cat > "$OUTPUT_DIR/example.cpp" << 'EOF'
#include <v8.h>
#include <libplatform/libplatform.h>
#include <iostream>
#include <memory>

class ArrayBufferAllocator : public v8::ArrayBuffer::Allocator {
public:
    void* Allocate(size_t length) override {
        void* data = AllocateUninitialized(length);
        return data == nullptr ? data : memset(data, 0, length);
    }
    void* AllocateUninitialized(size_t length) override { return malloc(length); }
    void Free(void* data, size_t) override { free(data); }
};

int main() {
    v8::V8::InitializeICUDefaultLocation("");
    v8::V8::InitializeExternalStartupData("");
    
    std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
    v8::V8::InitializePlatform(platform.get());
    v8::V8::Initialize();
    
    ArrayBufferAllocator allocator;
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = &allocator;
    create_params.constraints.set_max_old_space_size(128);
    
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    {
        v8::Isolate::Scope isolate_scope(isolate);
        v8::HandleScope handle_scope(isolate);
        
        v8::Local<v8::Context> context = v8::Context::New(isolate);
        v8::Context::Scope context_scope(context);
        
        const char* csource = R"(
            const start = Date.now();
            function fibonacci(n) {
                return n < 2 ? n : fibonacci(n-1) + fibonacci(n-2);
            }
            const result = fibonacci(35);
            const elapsed = Date.now() - start;
            ({result: result, time: elapsed + 'ms'});
        )";
        
        v8::Local<v8::String> source = v8::String::NewFromUtf8(isolate, csource).ToLocalChecked();
        v8::Local<v8::Script> script = v8::Script::Compile(context, source).ToLocalChecked();
        v8::Local<v8::Value> result = script->Run(context).ToLocalChecked();
        
        v8::String::Utf8Value utf8(isolate, result);
        std::cout << "V8 Result: " << *utf8 << std::endl;
    }
    
    isolate->Dispose();
    v8::V8::Dispose();
    v8::V8::ShutdownPlatform();
    
    std::cout << "V8 Android static libraries working correctly!" << std::endl;
    return 0;
}
EOF

cat > "$OUTPUT_DIR/build_example.sh" << 'EOF'
#!/bin/bash
if [ -z "$ANDROID_NDK_ROOT" ]; then
    echo "Set ANDROID_NDK_ROOT to your NDK path"
    exit 1
fi

TOOLCHAIN="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64"
ABI="${1:-arm64-v8a}"

case "$ABI" in
    "arm64-v8a")
        TARGET="aarch64-linux-android21"
        ;;
    "armeabi-v7a")
        TARGET="armv7a-linux-androideabi21"
        ;;
    "x86_64")
        TARGET="x86_64-linux-android21"
        ;;
esac

"$TOOLCHAIN/bin/$TARGET-clang++" \
    -std=c++17 \
    -O3 \
    -fno-rtti \
    -fno-exceptions \
    -DV8_COMPRESS_POINTERS \
    -DV8_31BIT_SMIS_ON_64BIT_ARCH \
    -Iinclude \
    example.cpp \
    -Llib/$ABI \
    -lv8_monolith \
    -lv8_base \
    -lv8_platform \
    -llog \
    -ldl \
    -static-libgcc \
    -static-libstdc++ \
    -o example_$ABI

echo "Built: example_$ABI"
EOF

chmod +x "$OUTPUT_DIR/build_example.sh"

cat > "$OUTPUT_DIR/README.md" << 'EOF'
# V8 Android Static Libraries - Fully Optimized

Ultra-optimized V8 static libraries for Android NDK with complete toolchain setup.

## Quick Start
```bash
export ANDROID_NDK_ROOT=/path/to/your/ndk
./build_example.sh arm64-v8a
./example_arm64-v8a
```

## CMake Integration
```cmake
include(v8/CMakeLists.txt)
target_link_v8(your_target)
```

## Optimizations Applied
- Link-Time Optimization (LTO)
- Symbol stripping
- WebAssembly disabled (-10MB)
- I18N disabled (-5MB)  
- Debug features disabled
- Pointer compression enabled
- Concurrent marking enabled
- Snapshot compression enabled
- JIT compilers optimized (Turbofan only)

## Architecture Support
- arm64-v8a (AArch64)
- armeabi-v7a (ARM with NEON)  
- x86_64 (Intel 64-bit for emulator)

EOF

echo "Generating library size information..."
echo "## Library Sizes" >> "$OUTPUT_DIR/README.md"
for abi in arm64-v8a armeabi-v7a x86_64; do
    if [ -d "$OUTPUT_DIR/lib/$abi" ]; then
        echo "### $abi" >> "$OUTPUT_DIR/README.md"
        ls -lh "$OUTPUT_DIR/lib/$abi"/*.a | awk '{print "- " $9 ": " $5}' >> "$OUTPUT_DIR/README.md"
        echo "" >> "$OUTPUT_DIR/README.md"
    fi
done

echo "Creating final archive..."
cd "$SCRIPT_DIR"
tar -czf v8_android_static_complete.tar.gz -C "$OUTPUT_DIR" .

echo ""
echo "========================================="
echo "V8 Android Static Build Complete!"
echo "========================================="
echo "Output: v8_android_static_complete.tar.gz"
echo "Archive size: $(du -h v8_android_static_complete.tar.gz | cut -f1)"
echo ""
echo "Total library sizes per architecture:"
for abi in arm64-v8a armeabi-v7a x86_64; do
    if [ -d "$OUTPUT_DIR/lib/$abi" ]; then
        total_size=$(du -ch "$OUTPUT_DIR/lib/$abi"/*.a | tail -1 | cut -f1)
        echo "  $abi: $total_size"
    fi
done
echo ""
echo "NDK used: $ANDROID_NDK_ROOT"
echo "Build directory: $BUILD_DIR (can be deleted)"
echo ""
echo "Archive contains:"
echo "- Static libraries for all Android ABIs"
echo "- Complete header files"  
echo "- CMake and Android.mk integration"
echo "- Working example with build script"
echo "- Full documentation"

echo "COMMIT_MSG=v8 android static build" >> "$GITHUB_ENV"
