#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting setup for PRO SCAN HEVEN Tool...${NC}"

# Check internet connection
if ! ping -c 1 google.com &> /dev/null; then
    echo -e "${RED}No internet connection. Connect and try again.${NC}"
    exit 1
fi

# Update Termux and install basic packages
echo -e "${GREEN}Installing basic packages...${NC}"
pkg update -y && pkg upgrade -y
pkg install python git nmap tsu rust clang -y || { echo -e "${RED}Failed to install packages. Check package manager.${NC}"; exit 1; }

# Set up Rust environment
echo -e "${GREEN}Setting up Rust environment...${NC}"
export CARGO_BUILD_TARGET=aarch64-linux-android
export RUSTFLAGS="-C linker=clang"
source $HOME/.cargo/env 2>/dev/null || echo -e "${YELLOW}Rust environment not found, continuing...${NC}"

# Create and activate virtual environment
echo -e "${GREEN}Creating virtual environment...${NC}"
cd $HOME
python -m venv pro_scan_venv || { echo -e "${RED}Failed to create virtual environment.${NC}"; exit 1; }
source pro_scan_venv/bin/activate || { echo -e "${RED}Failed to activate virtual environment.${NC}"; exit 1; }

# Install Python dependencies from requirements.txt
echo -e "${GREEN}Installing Python libraries from requirements.txt...${NC}"
cd $HOME/PRO-SCAN-HEVEN
if [ -f requirements.txt ]; then
    pip install --no-warn-script-location -r requirements.txt || {
        echo -e "${RED}Pip failed. Upgrading pip and retrying...${NC}"
        pip install --upgrade pip
        pip install --no-warn-script-location -r requirements.txt || { echo -e "${RED}Failed to install Python libraries.${NC}"; exit 1; }
    }
else
    echo -e "${RED}requirements.txt not found! Installing dependencies directly...${NC}"
    pip install --no-warn-script-location requests beautifulsoup4 python-nmap reportlab cryptography==43.0.3 rich websocket-client dnspython || {
        echo -e "${RED}Pip failed. Upgrading pip and retrying...${NC}"
        pip install --upgrade pip
        pip install --no-warn-script-location requests beautifulsoup4 python-nmap reportlab cryptography==43.0.3 rich websocket-client dnspython || { echo -e "${RED}Failed to install Python libraries.${NC}"; exit 1; }
    }
fi

# Clone the repository
echo -e "${GREEN}Cloning repository...${NC}"
cd $HOME
[ -d "PRO-SCAN-HEVEN" ] && { echo -e "${RED}Removing old PRO-SCAN-HEVEN directory...${NC}"; rm -rf PRO-SCAN-HEVEN; }
git clone https://github.com/menakajanith/PRO-SCAN-HEVEN.git || { echo -e "${RED}Failed to clone repository.${NC}"; exit 1; }
cd PRO-SCAN-HEVEN

# Run the tool
echo -e "${GREEN}Running PRO SCAN HEVEN Tool...${NC}"
if command -v tsu &> /dev/null; then
    tsu -c "python3 pro_scan_heven.py" || python3 pro_scan_heven.py
else
    python3 pro_scan_heven.py
fi

echo -e "${GREEN}Done!${NC}"
