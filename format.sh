#!/bin/bash

if [ $# -eq 0 ]; then
    find \( -type f -name '*.c' -or -name '*.h' -or -name '*.cpp' \
            -or -name '*.cc' -or -name '*.hpp' \) -exec "$0" {} \;
    exit 0
fi

if [ $# -gt 1 ]; then
    echo 'pass only one file at a time'
    exit 1
fi

#dos2unix "$1"
clang-format -i "$1"

exit 0
