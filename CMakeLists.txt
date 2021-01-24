cmake_minimum_required(VERSION 3.17)
project(project2 C)

set(CMAKE_C_STANDARD 99)

add_executable(project2 mirsa_genkeys.c mirsa_lib.h mirsa_lib.c mirsa_rw.c)