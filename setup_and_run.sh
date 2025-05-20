#!/bin/bash

# Update Termux and install dependencies
pkg update -y && pkg upgrade -y
pkg install python git nmap -y

# Install pip if not already installed
python -m ensurepip --upgrade
python -m pip install --upgrade pip

# Clone the repository
REPO_DIR="$HOME/pro-scan-heven"
if [ -d "$REPO_DIR" ]; then
    rm -rf "$REPO_DIR"
fi
git clone https://github.com/menakajanith/PRO-SCAN-HEVEN.git "$REPO_DIR"
cd "$REPO_DIR"

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install requests beautifulsoup4 python-nmap reportlab cryptography rich websocket-client dnspython

# Run the main script
python main.py
