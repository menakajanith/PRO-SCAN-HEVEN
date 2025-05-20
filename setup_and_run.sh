#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
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
pkg install python git nmap tsu -y || { echo -e "${RED}Failed to install packages. Check package manager.${NC}"; exit 1; }

# Install Python dependencies
echo -e "${GREEN}Installing Python libraries...${NC}"
pip install --no-warn-script-location requests beautifulsoup4 python-nmap reportlab cryptography rich websocket-client dnspython || {
    echo -e "${RED}Pip failed. Upgrading pip and retrying...${NC}"
    pip install --upgrade pip
    pip install --no-warn-script-location requests beautifulsoup4 python-nmap reportlab cryptography rich websocket-client dnspython || { echo -e "${RED}Failed to install Python libraries.${NC}"; exit 1; }
}

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
