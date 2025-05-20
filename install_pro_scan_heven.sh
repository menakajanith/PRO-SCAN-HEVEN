#!/data/data/com.termux/files/usr/bin/bash

# Update and upgrade Termux packages
pkg update && pkg upgrade -y

# Install curl and git
pkg install curl git -y

# Install nmap (required for python-nmap)
pkg install nmap -y

# Install Python and pip
pkg install python -y

# Install Python dependencies
pip install requests dnspython python-nmap beautifulsoup4 reportlab cryptography rich websocket-client

# Define repository URL
REPO_URL="https://github.com/menakajanith/PRO-SCAN-HEVEN.git"
REPO_DIR="PRO-SCAN-HEVEN"

# Check if repository directory exists, remove it if it does
if [ -d "$REPO_DIR" ]; then
    rm -rf "$REPO_DIR"
fi

# Clone the repository
git clone "$REPO_URL"

# Check if cloning was successful
if [ $? -eq 0 ]; then
    echo "Repository cloned successfully to $REPO_DIR"
else
    echo "Failed to clone repository"
    exit 1
fi

# Navigate to the repository directory
cd "$REPO_DIR" || exit

# Check if pro_scan_heven.py exists
if [ -f "pro_scan_heven.py" ]; then
    # Run the Python script
    python pro_scan_heven.py
else
    echo "Error: pro_scan_heven.py not found in $REPO_DIR"
    exit 1
fi
