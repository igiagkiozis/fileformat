## JsonCpp

JsonCpp meta repository that allows easy usage of [jsoncpp](https://github.com/open-source-parsers/jsoncpp) across several interlinked projects.

## Overview

The repository contains a single `CMakeLists.txt` file which gets JsonCpp as an external project and exposes its targets.

## Use

A single target named `jsoncpp` is exposed. It can be used as follows:
```cmake
target_link_libraries(project-that-needs-jsoncpp jsoncpp)
```

## Requirements

* A compiler supporting C++14
 * On Windows, only Microsoft Visual C++ is supported (version >= Visual Studio 2015).
* CMake (version >= 3.6)

## License

Copyright (c) 2017 Avast Software, licensed under the MIT license. See the `LICENSE` file for more details.

See the `LICENSE-THIRD-PARTY` file for the JsonCpp project license.
