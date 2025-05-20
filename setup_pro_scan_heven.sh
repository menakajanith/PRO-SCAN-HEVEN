#!/data/data/com.termux/files/usr/bin/bash

# Update and upgrade Termux packages
pkg update && pkg upgrade -y

# Install curl, git, nmap, and python
pkg install curl git nmap python -y

# Check if requirements.txt exists and install dependencies
REPO_DIR="pro-scan-heven"
if [ -f "$REPO_DIR/requirements.txt" ]; then
    echo "Installing Python dependencies from requirements.txt..."
    pip install -r "$REPO_DIR/requirements.txt"
else
    echo "requirements.txt not found, installing individual packages..."
    pip install requests dnspython python-nmap beautifulsoup4 reportlab cryptography rich websocket-client
fi

# Check if repository directory exists
if [ ! -d "$REPO_DIR" ]; then
    # Define repository URL
    REPO_URL="https://github.com/menakajanith/PRO-SCAN-HEVEN.git"
    # Clone the repository
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
    # Run the Python script
    echo "Running pro_scan_heven.py..."
    python pro_scan_heven.py
else
    echo "Error: pro_scan_heven.py not found in $REPO_DIR"
    exit 1
fi
