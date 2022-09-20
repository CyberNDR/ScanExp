# ScanExp
ScanExp automates the scanning of any machine's open ports via the ip address and performs a brute force attack on ports 20, 21 for the FTP protocol, port 22 for the SSH protocol and port 25 for the SMTP protocol, providing the choice between the use of two different wordlists for the username and password or two personalized wordlists chosen by the user.
# Installation
```# Git Clone
git clone https://github.com/CyberNDR/ScanExp.git

# change the current directory to ScanExp
cd ScanExp

# Install requirements
pip install -r requirements.txt

# Run the program

python ScanExp.py
