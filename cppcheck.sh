#!/bin/bash
cppcheck --enable=all --error-exitcode=1 \
    --suppress=missingIncludeSystem \
    --suppress=unusedFunction \
    --suppress=unusedStructMember \
    --inline-suppr \
    src/*.h src/*.cpp