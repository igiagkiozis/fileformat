cmake_minimum_required(VERSION 3.9)

set(FILEFORMAT_SOURCES
	utils/format_detection.cpp
	utils/conversions.cpp
	utils/other.cpp
	utils/asn1.cpp
	utils/file_io.cpp
	format_factory.cpp
	types/dotnet_headers/blob_stream.cpp
	types/dotnet_headers/user_string_stream.cpp
	types/dotnet_headers/guid_stream.cpp
	types/dotnet_headers/clr_header.cpp
	types/dotnet_headers/string_stream.cpp
	types/dotnet_headers/metadata_stream.cpp
	types/dotnet_headers/metadata_tables.cpp
	types/dotnet_headers/metadata_header.cpp
	types/pdb_info/pdb_info.cpp
	types/symbol_table/symbol_table.cpp
	types/symbol_table/macho_symbol.cpp
	types/symbol_table/symbol.cpp
	types/symbol_table/elf_symbol.cpp
	types/rich_header/rich_header.cpp
	types/rich_header/linker_info.cpp
	types/import_table/import.cpp
	types/import_table/import_table.cpp
	types/export_table/export.cpp
	types/export_table/export_table.cpp
	types/relocation_table/relocation_table.cpp
	types/relocation_table/relocation.cpp
	types/resource_table/resource.cpp
	types/resource_table/resource_table.cpp
	types/resource_table/resource_tree.cpp
	types/certificate_table/certificate.cpp
	types/certificate_table/certificate_table.cpp
	types/dotnet_types/dotnet_type_reconstructor.cpp
	types/dotnet_types/dotnet_class.cpp
	types/dotnet_types/dotnet_property.cpp
	types/dotnet_types/dotnet_field.cpp
	types/dotnet_types/dotnet_type.cpp
	types/dotnet_types/dotnet_data_types.cpp
	types/dotnet_types/dotnet_parameter.cpp
	types/dotnet_types/dotnet_method.cpp
	types/sec_seg/elf_section.cpp
	types/sec_seg/elf_segment.cpp
	types/sec_seg/segment.cpp
	types/sec_seg/pe_coff_section.cpp
	types/sec_seg/sec_seg.cpp
	types/sec_seg/section.cpp
	types/sec_seg/macho_section.cpp
	types/dynamic_table/dynamic_entry.cpp
	types/dynamic_table/dynamic_table.cpp
	types/strings/string.cpp
	file_format/pe/pe_format_parser/pe_format_parser64.cpp
	file_format/pe/pe_format_parser/pe_format_parser.cpp
	file_format/pe/pe_format_parser/pe_format_parser32.cpp
	file_format/pe/pe_format.cpp
	file_format/coff/coff_format.cpp
	file_format/intel_hex/intel_hex_parser/intel_hex_tokenizer.cpp
	file_format/intel_hex/intel_hex_parser/intel_hex_parser.cpp
	file_format/intel_hex/intel_hex_format.cpp
	file_format/macho/macho_format.cpp
	file_format/raw_data/raw_data_format.cpp
	file_format/file_format.cpp
	file_format/elf/elf_format.cpp
)

if(NOT TARGET fileformat)

	add_library(fileformat STATIC ${FILEFORMAT_SOURCES})
	target_link_libraries(fileformat fileformat-crypto retdec-config tl-cpputils pelib elfio llvm)
	target_include_directories(fileformat PUBLIC ${PROJECT_SOURCE_DIR}/include/)

endif()
