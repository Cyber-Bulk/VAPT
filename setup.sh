#!/bin/bash
echo "Setting up Python Penetration Testing Tool"
echo "----------------------------------------"

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
mkdir -p logs
mkdir -p reports

# Set permissions
chmod +x main.py

echo ""
echo "Setup complete!"
echo "To run the tool: ./main.py --target TARGET_URL --accept-terms [--recon] [--scan] [--exploit]"
echo "Remember to always get proper authorization before testing any system."