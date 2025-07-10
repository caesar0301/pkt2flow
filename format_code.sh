#!/bin/bash

# format_code.sh - Format C and C++ code using clang-format
# Usage: ./format_code.sh [--check] [--fix]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
CHECK_ONLY=false
FIX_CODE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --check)
            CHECK_ONLY=true
            shift
            ;;
        --fix)
            FIX_CODE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--check] [--fix]"
            echo "  --check: Only check formatting without making changes"
            echo "  --fix:   Fix formatting issues (default if no flag provided)"
            echo "  -h, --help: Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

# If no flags provided, default to fixing
if [[ "$CHECK_ONLY" == false && "$FIX_CODE" == false ]]; then
    FIX_CODE=true
fi

# Check if clang-format is available
if ! command -v clang-format &> /dev/null; then
    echo -e "${RED}Error: clang-format is not installed${NC}"
    echo "Install it with:"
    echo "  macOS: brew install clang-format"
    echo "  Ubuntu/Debian: sudo apt-get install clang-format"
    exit 1
fi

# Get clang-format version
CLANG_FORMAT_VERSION=$(clang-format --version | head -n1 | cut -d' ' -f3 | cut -d'.' -f1)
echo -e "${YELLOW}Using clang-format version: $(clang-format --version | head -n1)${NC}"

# Define source directories and file patterns
SOURCE_DIRS=("src" "tests" "examples")
FILE_PATTERNS=("*.cpp" "*.h" "*.hpp")

# Collect all files to format
FILES_TO_FORMAT=()
for dir in "${SOURCE_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        for pattern in "${FILE_PATTERNS[@]}"; do
            while IFS= read -r -d '' file; do
                FILES_TO_FORMAT+=("$file")
            done < <(find "$dir" -name "$pattern" -type f -print0 2>/dev/null)
        done
    fi
done

if [[ ${#FILES_TO_FORMAT[@]} -eq 0 ]]; then
    echo -e "${YELLOW}No source files found to format${NC}"
    exit 0
fi

echo -e "${YELLOW}Found ${#FILES_TO_FORMAT[@]} files to process:${NC}"
for file in "${FILES_TO_FORMAT[@]}"; do
    echo "  $file"
done
echo

# Function to check formatting
check_formatting() {
    local has_issues=false
    
    for file in "${FILES_TO_FORMAT[@]}"; do
        if [[ -f "$file" ]]; then
            if ! clang-format --dry-run --Werror "$file" >/dev/null 2>&1; then
                echo -e "${RED}✗ $file${NC}"
                has_issues=true
            else
                echo -e "${GREEN}✓ $file${NC}"
            fi
        fi
    done
    
    if [[ "$has_issues" == true ]]; then
        echo -e "\n${RED}Formatting issues found!${NC}"
        echo "Run '$0 --fix' to automatically fix formatting issues."
        exit 1
    else
        echo -e "\n${GREEN}All files are properly formatted!${NC}"
    fi
}

# Function to fix formatting
fix_formatting() {
    local fixed_count=0
    
    for file in "${FILES_TO_FORMAT[@]}"; do
        if [[ -f "$file" ]]; then
            echo -n "Formatting $file... "
            
            # Create a temporary file
            temp_file=$(mktemp)
            
            # Format the file
            if clang-format "$file" > "$temp_file"; then
                # Check if the file actually changed
                if ! cmp -s "$file" "$temp_file"; then
                    mv "$temp_file" "$file"
                    echo -e "${GREEN}✓${NC}"
                    ((fixed_count++))
                else
                    echo -e "${YELLOW}no changes${NC}"
                fi
            else
                echo -e "${RED}✗ error${NC}"
                rm -f "$temp_file"
            fi
        fi
    done
    
    echo -e "\n${GREEN}Formatting complete! Fixed $fixed_count files.${NC}"
}

# Main execution
if [[ "$CHECK_ONLY" == true ]]; then
    echo -e "${YELLOW}Checking code formatting...${NC}"
    check_formatting
elif [[ "$FIX_CODE" == true ]]; then
    echo -e "${YELLOW}Fixing code formatting...${NC}"
    fix_formatting
fi 