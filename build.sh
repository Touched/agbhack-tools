
#!/bin/bash

set -e

if [ "$BUILD_ARCH" == "x86" ]; then
    cmake -DCMAKE_BUILD_TYPE=Release . -DCMAKE_CXX_FLAGS=-m32 && make -j 2
else
    cmake -DCMAKE_BUILD_TYPE=Release . && make -j 2
fi
