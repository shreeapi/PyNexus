#!/usr/bin/env bash
# install.sh - Quick setup for PyNexus Scanner on Debian/Kali/Ubuntu.
#
# Usage:
#   chmod +x install.sh
#   ./install.sh

set -e

echo "==> PyNexus Scanner setup"

if ! command -v python3 &> /dev/null; then
    echo "[!] python3 not found. Installing..."
    sudo apt update && sudo apt install -y python3 python3-pip python3-venv
fi

echo "==> Creating virtual environment (venv/)"
python3 -m venv venv
source venv/bin/activate

echo "==> Installing Python dependencies"
pip install --upgrade pip
pip install -r requirements.txt

echo "==> Checking for libpcap (needed for ARP discovery / --syn)"
if ! dpkg -s libpcap-dev &> /dev/null 2>&1; then
    echo "[!] libpcap-dev not detected. Installing (needed for ARP + SYN scan)..."
    sudo apt install -y libpcap-dev
fi

echo ""
echo "==> Done. Activate the environment with:"
echo "      source venv/bin/activate"
echo "==> Then run:"
echo "      python3 main.py discover"
echo "      python3 main.py scan <target>"
