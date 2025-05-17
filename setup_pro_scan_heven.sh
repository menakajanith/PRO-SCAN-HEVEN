#!/bin/bash

# Variables
REPO_URL="https://raw.githubusercontent.com/menakajanith/PRO-SCAN-HEVEN/main"
SCRIPT_NAME="pro_scan_heven.py"
REQUIREMENTS="requirements.txt"
WORKDIR="$HOME/pro-scan-heven"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Banner
echo -e "${GREEN}=== PRO SCAN HEVEN Tool Setup ===${NC}"

# Check for curl
if ! command_exists curl; then
    echo -e "${RED}Error: curl is not installed. Installing...${NC}"
    pkg install curl || sudo apt-get install curl -y || sudo yum install curl -y
fi

# Check for git
if ! command_exists git; then
    echo -e "${RED}Error: git is not installed. Installing...${NC}"
    pkg install git || sudo apt-get install git -y || sudo yum install git -y
fi

# Check for Python
if ! command_exists python3; then
    echo -e "${RED}Error: Python3 is not installed. Installing...${NC}"
    pkg install python || sudo apt-get install python3 -y || sudo yum install python3 -y
fi

# Create working directory
mkdir -p "$WORKDIR"
cd "$WORKDIR" || { echo -e "${RED}Failed to access $WORKDIR${NC}"; exit 1; }

# Check if repository exists locally
if [ -d ".git" ]; then
    echo -e "${YELLOW}Updating existing repository...${NC}"
    git pull origin main
else
    echo -e "${YELLOW}Cloning repository...${NC}"
    git clone https://github.com/menakajanith/PRO-SCAN-HEVEN.git .
fi

# Download script and requirements if git fails
if [ ! -f "$SCRIPT_NAME" ]; then
    echo -e "${YELLOW}Downloading $SCRIPT_NAME using curl...${NC}"
    curl -s -o "$SCRIPT_NAME" "$REPO_URL/$SCRIPT_NAME"
fi
if [ ! -f "$REQUIREMENTS" ]; then
    echo -e "${YELLOW}Downloading $REQUIREMENTS using curl...${NC}"
    curl -s -o "$REQUIREMENTS" "$REPO_URL/$REQUIREMENTS"
fi

# Check if files were downloaded
if [ ! -f "$SCRIPT_NAME" ] || [ ! -f "$REQUIREMENTS" ]; then
    echo -e "${RED}Error: Failed to download required files${NC}"
    exit 1
fi

# Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
pip install --upgrade pip
pip install -r "$REQUIREMENTS"

# Install nmap for Termux or PC
if ! command_exists nmap; then
    echo -e "${YELLOW}Installing nmap...${NC}"
    pkg install nmap || sudo apt-get install nmap -y || sudo yum install nmap -y
fi

# Port scanning warning
echo -e "${YELLOW}Warning: Unauthorized port scanning may violate laws or terms of service. Ensure you have permission.${NC}"

# Run the script
echo -e "${GREEN}Running PRO SCAN HEVEN Tool...${NC}"
python3 "$SCRIPT_NAME"

# Cleanup (optional)
echo -e "${YELLOW}Do you want to keep the working directory? (y/n)${NC}"
read -r KEEP_DIR
if [ "$KEEP_DIR" != "y" ] && [ "$KEEP_DIR" != "Y" ]; then
    cd ..
    rm -rf "$WORKDIR"
    echo -e "${GREEN}Working directory removed${NC}"
fi
