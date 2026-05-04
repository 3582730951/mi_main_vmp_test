cmake_minimum_required(VERSION 3.20)
project(VMPIRCore LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(LLVM 14 REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

add_library(VMPPassPlugin MODULE
  Bytecode.cpp
  Deterministic.cpp
  OpcodeMap.cpp
  ProtectionConfig.cpp
  llvm/VMPPassPlugin.cpp
)

target_include_directories(VMPPassPlugin SYSTEM PRIVATE
  ${LLVM_INCLUDE_DIRS}
)
target_compile_definitions(VMPPassPlugin PRIVATE
  ${LLVM_DEFINITIONS}
)
target_compile_options(VMPPassPlugin PRIVATE
  -Wall
  -Wextra
  -Werror
  -Wno-unused-parameter
  -fno-rtti
)

set_target_properties(VMPPassPlugin PROPERTIES
  PREFIX ""
  OUTPUT_NAME "VMPPassPlugin"
)

if(APPLE)
  set_target_properties(VMPPassPlugin PROPERTIES
    LINK_FLAGS "-undefined dynamic_lookup"
  )
endif()
