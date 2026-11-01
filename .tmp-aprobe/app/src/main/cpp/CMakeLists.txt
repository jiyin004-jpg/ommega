cmake_minimum_required(VERSION 3.22.1)
project(aprobes CXX)
add_library(hiddenapi SHARED hiddenapi.cpp rawnative.cpp)
target_link_libraries(hiddenapi log)
