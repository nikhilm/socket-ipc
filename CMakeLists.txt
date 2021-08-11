cmake_minimum_required(VERSION 3.10)
project(socket-ipc)
set(CMAKE_CXX_STANDARD 17)

add_subdirectory(benchmark)

add_executable(socket_bm socket_bm.cc)
target_link_libraries(socket_bm benchmark::benchmark)
