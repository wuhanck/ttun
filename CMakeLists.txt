cmake_minimum_required(VERSION 3.5)

project(ttun)
set(CMAKE_C_STANDARD 11)

add_executable(ttun
    ttun.c
)

target_link_libraries(ttun
    PRIVATE
        event
)
