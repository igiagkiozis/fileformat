
cmake_minimum_required(VERSION 3.6)

project(fileformat CXX)

# Set the default build type to 'Release'
if (NOT CMAKE_BUILD_TYPE)
	set(default_build_type "Release")
	message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
	set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
endif()

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

option(FILEFORMAT_DOC "Build public API documentation (requires Doxygen)." OFF)
option(FILEFORMAT_TESTS "Build tests." OFF)

# Build all external projects in the same directory that is directly inside the
# build directory. This reduces path lengths, which is important on Windows as
# there is a limit on how long a path can be.
# However, do it only when this is the top-level project. Otherwise, use the
# directory provided by the top-level project (we do not want to override it).
if("${CMAKE_PROJECT_NAME}" STREQUAL "${PROJECT_NAME}")
	set_directory_properties(PROPERTIES EP_PREFIX "${PROJECT_BINARY_DIR}/external")
endif()

add_subdirectory(deps)
if(FILEFORMAT_DOC)
	add_subdirectory(doc)
endif()
add_subdirectory(src)
if(FILEFORMAT_TESTS)
	add_subdirectory(tests)
endif()
