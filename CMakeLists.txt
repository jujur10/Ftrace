cmake_minimum_required(VERSION 3.26)
project(Ftrace C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED YES)
set(CMAKE_C_FLAGS "-Wall -Wextra")

add_library(build_configs INTERFACE)

target_compile_options(build_configs INTERFACE
    $<$<CONFIG:DEBUG>:-ggdb3>
    $<$<CONFIG:DEBUG>:-Og>
    $<$<CONFIG:RELEASE>:-Ofast>
    -march=native
    -flto=auto
)

target_compile_definitions(build_configs INTERFACE
    $<$<CONFIG:DEBUG>:DEBUG>
    $<$<CONFIG:RELEASE>:NDEBUG>
    BRACKET_O={
    BRACKET_C=}
    "SEMICOLON=\;"
    COLON=:
    "EQUAL=\="
    "BREAK=break\;"
)

target_link_options(build_configs INTERFACE
    -flto=auto
)

add_executable(ftrace
    src/main.c
    src/ftrace.c
    src/print_syscall.c
    src/print_utils.c
    src/signal.c
    src/call_near_relative.c
    src/elf_utils.c
    src/call_near_absolute.c
    src/memory_map_utils.c
    src/find_library.c
    src/find_function_name.c
)

target_include_directories(ftrace PRIVATE
    include
)

target_link_libraries(ftrace PRIVATE
    build_configs
    elf
)

set_target_properties(ftrace PROPERTIES
    OUTPUT_NAME ftrace
)

add_custom_command(TARGET ftrace
    POST_BUILD COMMAND cp ftrace ../
)
