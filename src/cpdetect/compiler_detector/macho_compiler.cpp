/**
 * @file src/cpdetect/compiler_detector/macho_compiler.cpp
 * @brief Methods of MachOCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "cpdetect/compiler_detector/heuristics/macho_heuristics.h"
#include "cpdetect/compiler_detector/macho_compiler.h"
#include "cpdetect/settings.h"
#include "cpdetect/signatures/yara/database/database.h"

using namespace fileformat;

namespace cpdetect {

/**
 * Constructor
 */
MachOCompiler::MachOCompiler(
		fileformat::MachOFormat &parser, DetectParams &params, ToolInformation &tools)
	: CompilerDetector(parser, params, tools)
{
	heuristics = new MachOHeuristics(parser, *search, toolInfo);
	externalSuffixes = EXTERNAL_DATABASE_SUFFIXES;

	tl_cpputils::FilesystemPath path(pathToShared);
	path.append(YARA_RULES_PATH + "macho/");
	auto bitWidth = parser.getWordLength();

	if (parser.isFatBinary())
	{
		for (auto it = path.begin(), end = path.end(); it != end; it++) {
			if (it->isFile()) {
				internalPaths.emplace_back(it->getAbsolutePath());
			}
		}
	}
	else
	{
		switch(targetArchitecture)
		{
			case Architecture::X86:
				path.append("x86.yarac");
				break;

			case Architecture::X86_64:
				path.append("x64.yarac");
				break;

			case Architecture::ARM:
				if (bitWidth == 32) {
					path.append("arm.yarac");
				}
				else {
					// There are no 64-bit ARM signatures for now.
				}
				break;

			case Architecture::POWERPC:
				if (bitWidth == 32) {
					path.append("ppc.yarac");
				}
				else {
					path.append("ppc64.yarac");
				}
				break;
		}

		if (path.isFile()) {
			internalPaths.emplace_back(path.getAbsolutePath());
		}
	}
}

} // namespace cpdetect
