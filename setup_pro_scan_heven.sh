#!/bin/bash

# Variables
REPO_URL="https://raw.githubusercontent.com/menakajanith/PRO-SCAN-HEVEN/main"
REPO_GIT="https://github.com/menakajanith/PRO-SCAN-HEVEN.git"
SCRIPT_NAME="pro_scan_heven.py"
REQUIREMENTS="requirements.txt"
WORKDIR="$HOME/pro-scan-heven"
PYTHON="python3"
PIP="pip3"

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

# Function to install packages
install_package() {
    local pkg="$1"
    echo -e "${YELLOW}Installing $pkg...${NC}"
    if command_exists pkg; then
        pkg install "$pkg" -y
    elif command_exists apt-get; then
        sudo apt-get install "$pkg" -y
    elif command_exists yum; then
        sudo yum install "$pkg" -y
    else
        echo -e "${RED}Error: Package manager not found for $pkg${NC}"
        exit 1
    fi
}

# Update Termux package lists
if command_exists pkg; then
    echo -e "${YELLOW}Updating Termux package lists...${NC}"
    pkg update -y && pkg upgrade -y
fi

# Check and install curl
if ! command_exists curl; then
    echo -e "${RED}Error: curl is not installed.${NC}"
    install_package curl
fi

# Check and install git
if ! command_exists git; then
    echo -e "${RED}Error: git is not installed.${NC}"
    install_package git
fi

# Check and install Python
if ! command_exists "$PYTHON"; then
    echo -e "${RED}Error: Python3 is not installed.${NC}"
    install_package python
fi

# Check and install nmap
if ! command_exists nmap; then
    echo -e "${RED}Error: nmap is not installed.${NC}"
    install_package nmap
fi

# Avoid pip upgrade in Termux to prevent conflicts
if command_exists pkg; then
    echo -e "${YELLOW}Ensuring pip is installed in Termux...${NC}"
    pkg install python-pip -y
fi

# Create working directory
mkdir -p "$WORKDIR"
cd "$WORKDIR" || { echo -e "${RED}Failed to access $WORKDIR${NC}"; exit 1; }

# Check if repository exists locally
if [ -d ".git" ]; then
    echo -e "${YELLOW}Updating existing repository...${NC}"
    git pull origin main || { echo -e "${RED}Failed to update repository${NC}"; exit 1; }
else
    echo -e "${YELLOW}Cloning repository...${NC}"
    git clone "$REPO_GIT" . || { echo -e "${RED}Failed to clone repository${NC}"; exit 1; }
fi

# Download script and requirements if git fails
if [ ! -f "$SCRIPT_NAME" ]; then
    echo -e "${YELLOW}Downloading $SCRIPT_NAME using curl...${NC}"
    curl -s -o "$SCRIPT_NAME" "$REPO_URL/$SCRIPT_NAME" || { echo -e "${RED}Failed to download $SCRIPT_NAME${NC}"; exit 1; }
fi
if [ ! -f "$REQUIREMENTS" ]; then
    echo -e "${YELLOW}Downloading $REQUIREMENTS using curl...${NC}"
    curl -s -o "$REQUIREMENTS" "$REPO_URL/$REQUIREMENTS" || { echo -e "${RED}Failed to download $REQUIREMENTS${NC}"; exit 1; }
fi

# Check if files were downloaded
if [ ! -f "$SCRIPT_NAME" ] || [ ! -f "$REQUIREMENTS" ]; then
    echo -e "${RED}Error: Required files not found. Check if repo is public and files exist.${NC}"
    exit 1
fi

# Verify requirements.txt is valid
if ! grep -qE '^[a-zA-Z0-9_-]+' "$REQUIREMENTS"; then
    echo -e "${RED}Error: requirements.txt is invalid or contains 404 error content${NC}"
    exit 1
fi

# Install Python dependencies
echo -e "${YELLOW}Installing Python dependencies...${NC}"
"$PIP" install -r "$REQUIREMENTS" || { echo -e "${RED}Failed to install dependencies${NC}"; exit 1; }

# Port scanning warning
echo -e "${YELLOW}Warning: Unauthorized port scanning may violate laws or terms of service. Ensure you have permission.${NC}"

# Run the script
echo -e "${GREEN}Running PRO SCAN HEVEN Tool...${NC}"
"$PYTHON" "$SCRIPT_NAME" || { echo -e "${RED}Failed to run $SCRIPT_NAME${NC}"; exit 1; }

# Cleanup (optional)
echo -e "${YELLOW}Do you want to keep the working directory? (y/n)${NC}"
read -r KEEP_DIR
if [ "$KEEP_DIR" != "y" ] && [ "$KEEP_DIR" != "Y" ]; then
    cd ..
    rm -rf "$WORKDIR"
    echo -e "${GREEN}Working directory removed${NC}"
fi
