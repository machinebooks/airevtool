cmake_minimum_required(VERSION 3.20)
project(AIrevPlugin)

set(CMAKE_CXX_STANDARD 17)

# Build both x64 and x32 variants
# Run cmake with -A x64 or -A Win32

set(X64DBG_ROOT "${CMAKE_SOURCE_DIR}/../x64dbg")

add_library(AIrevPlugin SHARED
    src/plugin.cpp
    src/command_handler.cpp
    src/websocket_server.cpp
)

target_include_directories(AIrevPlugin PRIVATE
    "${X64DBG_ROOT}/src/dbg"
    "${X64DBG_ROOT}/src/bridge"
    src
)

target_link_libraries(AIrevPlugin PRIVATE
    ws2_32
    "${CMAKE_SOURCE_DIR}/x64bridge.lib"
    "${CMAKE_SOURCE_DIR}/x64dbg.lib"
)

target_compile_definitions(AIrevPlugin PRIVATE
    _WINDOWS
    _USRDLL
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

# Suppress ntstatus.h macro redefinition warnings (C4005)
# and other common x64dbg SDK warnings
target_compile_options(AIrevPlugin PRIVATE
    /wd4005   # macro redefinition
    /wd4996   # deprecated functions
    /wd4267   # size_t conversion
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(AIrevPlugin PROPERTIES
        OUTPUT_NAME "AIrevPlugin"
        SUFFIX ".dp64"
    )
else()
    set_target_properties(AIrevPlugin PROPERTIES
        OUTPUT_NAME "AIrevPlugin"
        SUFFIX ".dp32"
    )
endif()

# Install to x64dbg plugins directory
install(TARGETS AIrevPlugin
    RUNTIME DESTINATION "${X64DBG_ROOT}/bin/plugins"
)
