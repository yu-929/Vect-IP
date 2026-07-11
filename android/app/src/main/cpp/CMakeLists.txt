cmake_minimum_required(VERSION 3.18)
project("vectbridge")

# Import the pre-built Go shared library
add_library(vect SHARED IMPORTED)
set_target_properties(vect PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libvect.so
)

add_library(vectbridge SHARED jni_bridge.c)
target_include_directories(vectbridge PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(vectbridge vect)

find_library(log-lib log)
target_link_libraries(vectbridge ${log-lib})