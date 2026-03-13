# Require at least CMake 3.20.
# CMake will stop if the installed version is older.
cmake_minimum_required(VERSION 3.20)

# Define the project and specify that it uses the C language.
# This tells CMake it must locate a C compiler.
project(Muninn_DAL C)

# file(GLOB_RECURSE DAL_SOURCES "src/*.c")

# Build a static library from the specified source file.
# STATIC libraries are archives (.lib on Windows, .a on Unix).
add_library(${PROJECT_NAME} STATIC
    #${DAL_SOURCES}
    src/DataUtilities.c
)

# Add the public header directory.
# PUBLIC means:
#   - This target uses the headers
#   - Any target linking this library will also inherit this include path
target_include_directories(${PROJECT_NAME}
    PUBLIC include
)

# Add the export macro for building the DLL
target_compile_definitions(${PROJECT_NAME}
    PRIVATE MUNINN_EXPORTS
)

# Force compilation using the ANSI C89 standard when using Clang.
# This bypasses CMake's language-dialect detection.
target_compile_options(${PROJECT_NAME}
    PRIVATE -std=c89
)

# --- Build Instructions ---
#
# Configure the project from a Visual Studio Developer Command Prompt
# (x64 Native Tools Command Prompt for VS).
#
# Configure:
#   cmake -S . -B build -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
#
# Build:
#   cmake --build build