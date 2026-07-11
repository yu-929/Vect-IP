cmake_minimum_required(VERSION 3.18)
project("vectbridge")

add_library(vectbridge SHARED jni_bridge.c)

target_include_directories(vectbridge PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Link against pre-built libvect.so from jniLibs
target_link_directories(vectbridge PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI})
target_link_libraries(vectbridge vect)

# Also need log for Go runtime debugging
find_library(log-lib log)
target_link_libraries(vectbridge ${log-lib})