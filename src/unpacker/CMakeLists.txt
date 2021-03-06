cmake_minimum_required(VERSION 3.9)

set(UNPACKER_SOURCES
	decompression/lzma/lzma_data.cpp
	decompression/nrv/nrv2d_data.cpp
	decompression/nrv/nrv2b_data.cpp
	decompression/nrv/nrv2e_data.cpp
	decompression/lzmat/lzmat_data.cpp
	signature.cpp
	dynamic_buffer.cpp
)

if(NOT TARGET unpacker)

	add_library(unpacker STATIC ${UNPACKER_SOURCES})
	target_link_libraries(unpacker loader)
	target_include_directories(unpacker PUBLIC ${PROJECT_SOURCE_DIR}/deps/fileformat/include/ ../../include/)

	# Disable the min() and max() macros to prevent errors when using e.g.
	# std::numeric_limits<...>::max()
	# (http://stackoverflow.com/questions/1904635/warning-c4003-and-errors-c2589-and-c2059-on-x-stdnumeric-limitsintmax).
	# Any target that includes "windows.h" needs to define this.
	if(MSVC)
		target_compile_definitions(unpacker PUBLIC NOMINMAX)
	endif()

endif()
