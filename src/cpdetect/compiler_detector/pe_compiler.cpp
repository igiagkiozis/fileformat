/**
 * @file src/cpdetect/compiler_detector/pe_compiler.cpp
 * @brief Methods of PeCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "cpdetect/compiler_detector/heuristics/pe_heuristics.h"
#include "cpdetect/compiler_detector/pe_compiler.h"
#include "cpdetect/settings.h"
#include "cpdetect/signatures/yara/database/database.h"

using namespace fileformat;

namespace cpdetect {

/**
 * Constructor
 */
PeCompiler::PeCompiler(fileformat::PeFormat &parser, DetectParams &params, ToolInformation &tools) : CompilerDetector(parser, params, tools)
{
	heuristics = new PeHeuristics(parser, *search, toolInfo);
	externalSuffixes = EXTERNAL_DATABASE_SUFFIXES;

	tl_cpputils::FilesystemPath path(pathToShared);
	path.append(YARA_RULES_PATH + "pe/");
	auto bitWidth = parser.getWordLength();

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
	}

	if (path.isFile()) {
		internalPaths.emplace_back(path.getAbsolutePath());
	}
}

} // namespace cpdetect
