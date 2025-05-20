#!/data/data/com.termux/files/usr/bin/bash

# Ensure Termux storage access
termux-setup-storage

# Update and upgrade Termux packages
pkg update && pkg upgrade -y

# Install system dependencies
pkg install curl git nmap python -y

# Ensure pip is installed and up-to-date
python -m ensurepip --upgrade
python -m pip install --upgrade pip

# Install all required Python packages explicitly
echo "Installing Python dependencies..."
python -m pip install requests dnspython python-nmap beautifulsoup4 reportlab cryptography rich websocket-client

# Check if repository directory exists
REPO_DIR="pro-scan-heven"
if [ ! -d "$REPO_DIR" ]; then
    # Clone the repository
    REPO_URL="https://github.com/menakajanith/PRO-SCAN-HEVEN.git"
    git clone "$REPO_URL"
    if [ $? -eq 0 ]; then
        echo "Repository cloned successfully to $REPO_DIR"
    else
        echo "Failed to clone repository"
        exit 1
    fi
else
    echo "Repository directory $REPO_DIR already exists, skipping clone"
fi

# Navigate to the repository directory
cd "$REPO_DIR" || exit

# Check if pro_scan_heven.py exists
if [ -f "pro_scan_heven.py" ]; then
    echo "Running pro_scan_heven.py..."
    python pro_scan_heven.py
else
    echo "Error: pro_scan_heven.py not found in $REPO_DIR"
    exit 1
fi
