cmake_minimum_required(VERSION 3.22.1)

project(xray_mobile_jni)

set(XRAY_FFI_ANDROID_DIR "$ENV{XRAY_FFI_ANDROID_DIR}")
if(NOT XRAY_FFI_ANDROID_DIR)
    get_filename_component(
        XRAY_FFI_ANDROID_DIR
        "${CMAKE_CURRENT_LIST_DIR}/../../../../../../target/mobile/android"
        ABSOLUTE
    )
endif()

add_library(xray_ffi SHARED IMPORTED)
set_target_properties(
    xray_ffi
    PROPERTIES
    IMPORTED_LOCATION "${XRAY_FFI_ANDROID_DIR}/jniLibs/${ANDROID_ABI}/libxray_ffi.so"
)

add_library(xray_mobile_jni SHARED xray_mobile_jni.cpp)
target_include_directories(xray_mobile_jni PRIVATE "${XRAY_FFI_ANDROID_DIR}/include")
target_link_libraries(xray_mobile_jni PRIVATE xray_ffi log)
