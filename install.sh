#!/bin/bash
sed -i 's/\r$//' main.py install.sh
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root (use sudo ./install.sh)"
  exit
fi

echo "[*] Installing SUPERNOVA Scanner..."

chmod +x main.py

TOOL_DIR=$(pwd)

ln -sf "$TOOL_DIR/main.py" /usr/local/bin/supernova

echo "[+] Installation complete!"
echo "[+] You can now run the tool from anywhere by typing: supernova"
