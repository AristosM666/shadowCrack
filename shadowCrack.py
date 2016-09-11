#!/usr/bin/env python
#
# ~ Project: shadowCrack v1.0
# ~ Written By: AristosM666
#
##############################
from __future__ import print_function
from itertools import product
from threading import Thread
from sys import exit, argv
from crypt import crypt
import string


__author__ = "aristosMiliaressis"
__title__ = "shadowCrack"
__version__ = 1.0


# Options
min_len = 0
max_len = -1
listUsers = False
brute = False
dictionary = ""
targets = []
userHash = ""
targetFile = ""


def helpPage(status):
    print(("USAGE: %s [op-mode] [targets]" % argv[0]))

    print("\nOperation Mode:")
    print("\t-d, --dictionary  <filename>  provide a dictionary file")
    print("\t-b, --brute                   use a brute-force attack")
    print("\t-L, --length      <min:max>   provide password length to be used for brute-forcing")
    #print("\t-C, --charset     <charset>   provide a charset to be used for brute-forcing")
    print("\t-l, --list                    list all users on the system and exit")
    print("\t-h, --help                    display this help page and exit")

    print("\nTargets:")
    print("\t-t, --targets  <target(s)>   provide a comma separated list of users to attack")
    print("\t-f, --file     <filename>    provide a text file to read hash(es) from")
    print("\t-H, --hash     <hash>        provide a hash from the command-line")
    
    print("\nDescription:")
    print(("\t%s is a password cracker for *nix systems," % __title__))
    print("\tit will try to find hashed passwords or get them as user input")
    print("\tand then crack them using a dictionary and/or brute-force attack.")
    exit(status)


def error(s):
    print(('\033[1;31m[!]\033[m %s' % s))


def fail(s):
    print(('\033[1;33m[-]\033[m %s' % s))


def success(s):
    print(('\033[1;32m[+]\033[m %s' % s))


def progress(s, end=True):
    if not end:
        print(('\033[1;37m[*]\033[m %s' % s), end="")
    else:
        print(('\033[1;37m[*]\033[m %s' % s))


def info(s):
    print(('\033[1;36m[:]\033[m %s' % s))


def terminate(errMsg, status=0):
    if status == 1:
        error(errMsg)
    else:
        fail(errMsg)
    progress("Aborting...")
    exit(status)
	

def errHandle(errno, fname):
    if "Errno 13" in str(errno):
        terminate(("Permission Denied: Can't Open '%s'" % fname), 1)
    elif "Errno 2" in str(errno):
        terminate(("File not Found: Can't Find '%s'" % fname), 1)
    else:
        terminate(("Unknown Error while Opening File '%s'" % fname), 1)


def bruteForce(_hash, user):
    global min_len
    global max_len

    try:
        salt = "$" + _hash.split('$')[1] + "$" + _hash.split('$')[2]
    except:
        terminate("Invalid Hash Format!", 1)

    charSet = string.letters + string.digits + string.punctuation
    length = min_len

    while length <= max_len:
        gen = product(charSet, repeat=length)
        for word in gen:
            wordStr = ''.join(word).strip('\n')
            hashedWord = crypt(wordStr, salt)
            progress(("Brute-forcing hash attempting phrase '%s'     \r" % wordStr), end=False)
            if hashedWord == _hash:
                print("\n")
                info(("Hash of '%s' Users Password Cracked: '%s'" % (user, wordStr)))
                return
        length += 1
    return


def dictionaryAttack(_hash, user, dictionary):
    try:
        fdict = open(dictionary, 'r')
    except Exception as err:
        errHandle(err, dictionary)
        exit(1)
    fdict.seek(0, 0)

    try:
        salt = "$" + _hash.split('$')[1] + "$" + _hash.split('$')[2]
    except:
    	fdict.close()
        terminate("Invalid Hash Format!", 1)
	
    for (count, word) in enumerate(fdict.readlines()):
        word = word.strip('\n')
        hashedWord = crypt(word, salt)
        progress(("Cracking hash, attempt %d phrase '%s'" % (count+1, word)), False)
        print("             \r", end="")
        if hashedWord == _hash:
            print("\n")
            info(("Hash of '%s' Users Password Cracked: '%s'" % (user, word)))
            fdict.close()
            return

    fail(("Password of '%s' Not Found!" % user))
    fdict.close()
    return


def parseHash(h):
    user = h[:h.find(':')]
    _hash = h.split(':')[0].strip('\n')

    if '$' not in _hash:
        _hash = h.split(':')[1].strip('\n')
            
    if _hash != '*' and _hash != '!':
        return _hash, user
    return '*', ''


def getTargets(fname):
    try:
        userFile = open(fname, 'r')
    except Exception as errno:
        errHandle(errno, fname)
        return None, None

    userList = []
    hashList = []
    for user in userFile.readlines():
        targetHash = user.split(':')[1].strip('\n')
        if len(targetHash) > 6:
            userList.append(user.split(':')[0])
            hashList.append(user.split(':')[1].strip('\n'))
    userFile.close()
    return userList, hashList


def getOpts():
    global listUsers
    global brute
    global dictionary
    global targets
    global userHash
    global targetFile
    global min_len
    global max_len

    i = 1
    while i < len(argv):
        if argv[i] == "-h" or argv[i] == "--help":
            helpPage(0)
        elif argv[i] == "-l" or argv[i] == "--list":
            listUsers = True
            break
        elif argv[i] == "-d" or argv[i] == "--dictionary":
            i += 1
            if i == len(argv):
                error("No Value Provided for Option '--dictionary'.\n")
                helpPage(1)
            dictionary = argv[i]
        elif argv[i] == "-t" or argv[i] == "--targets":
            i += 1
            if i == len(argv):
                error("No Value Provided for Option '--targets'.\n")
                helpPage(1)

            try:
                targets = (argv[i]).split(',')
            except:
                error(("Invalid Value '%s' for Option '--targets'.\n" % argv[i]))
                helpPage(1)
        elif argv[i] == "-H" or argv[i] == "--hash":
            i += 1
            if i == len(argv):
                error("No Value Provided for Option '--hash'.\n")
                helpPage(1)
            userHash = argv[i]
        elif argv[i] == "-f" or argv[i] == "--file":
            i += 1
            if i == len(argv):
                error("No Value Provided for Option '--file'.\n")
                helpPage(1)
            targetFile = argv[i]
        elif argv[i] == "-b" or argv[i] == "--brute":
            brute = True
        elif argv[i] == "-L" or argv[i] == "--length":
            i += 1
            if i == len(argv):
                error("No Value Provided for Option '--length'.\n")
                helpPage(1)
            
            try:
      	        s = (argv[i]).split(':')[0]
      	        if s != '':
      	            min_len = int(s)
      	        if s != argv[i]:
      	            s = (argv[i]).split(':')[1]
      	            if s != '':
      	                max_len = int(s)
      	    except:
      	        error(("Invalid value '%s' provided for option '--length'\n" % argv[i]))
      	        helpPage(1)
      	    if min_len > max_len:
      	        error("Minimum Length Greater Than Maximum Length!\n")
      	        helpPage(1)
      	    elif min_len < 0:
      	        error("Minimum Length Less Than Zero!\n")
      	        helpPage(1)
        else:
            error(("Invalid Argument '%s' Provided.\n" % argv[i]))
            helpPage(1)
        i += 1


def main():
    PASS_FILES = ['/etc/shadow', '/etc/passwd']
    global listUsers
    global brute
    global dictionary
    global targets
    global userHash
    global targetFile

    if not argv[1:]:
        helpPage(0)

    getOpts()

    if listUsers:
        progress("Searching for Users...")
        for fname in PASS_FILES:
            targets, hashList = getTargets(fname)
            if targets:
                break

        if targets:
            success(("%d User(s) Found." % len(targets)))
            info(("%s" % ", ".join(map(str, targets))))
        exit(1)
    elif not dictionary and not brute:
        terminate("No Dictionary File Provided.")
    elif not userHash and not targetFile and not targets:
        terminate("No Targets or Hashes Provided.")

    if userHash:
        _userHash, user = parseHash(userHash)
        if _userHash != '*':
            success(("Hash of '%s' Users Password Found.   " % user))
        else:
            error("Hash Section Not Found!\n")
            helpPage(1)
        
        if dictionary:
            progress("Attempting Dictionary Attack Against Provided Hash...")
            t2 = Thread(target=dictionaryAttack, args=(userHash, user, dictionary))
            t2.start()

        if brute:
            progress("Brute Forcing Provided Hash...")
            t1 = Thread(target=bruteForce, args=(userHash, user))
            t1.start()

    if targetFile:
        progress("Reading Hashes From Provided File...")
        try:
            hashFile = open(targetFile, 'r')
        except Exception as err:
            errHandle(err, targetFile)

        if dictionary:
            progress("Attempting Dictionary Attack Against Provided Hash(es)...\n")
        if brute:
            progress("Brute Forcing Provided Hash(es)...\n")

        for h in hashFile.readlines():
            _hash, user = parseHash(h)
            
            if _hash != '*':
                success(("Hash of '%s' Users Password Found.   " % user))
            else:
            	continue

            if dictionary:
                t1 = Thread(target=dictionaryAttack, args=(_hash, user, dictionary))
                t1.start()

            if brute:
                t2 = Thread(target=bruteForce, args=(_hash, user))
                t2.start()
        hashFile.close()

    if targets:
        progress("Searching for Users...")
        for fname in PASS_FILES:
            users, hashList = getTargets(fname)

            if not users:
                continue

            notFound = []
            for target in targets:
                for user in users:
                    if user == target:
                        success(("User '%s' Found" % str(target)))
                        break
                else:
                    fail(("User '%s' Not Found" % str(target)))
                    notFound.append(target)

            for target in notFound:
                targets.remove(target)

            if targets:
                break

        if not targets or not users:
            terminate("No Targets Found!")

        print("\n")
        progress("Attacking Provided User(s)...")

        for (i, target) in enumerate(targets):
            if dictionary:
                progress(("Attempting Dictionary Attack Against User '%s'" % target))
                t1 = Thread(target=dictionaryAttack, args=(hashList[i], target, dictionary))
                t1.start()

            if brute:
                progress(("Brute Forcing Hash of '%s' Users Password" % target))
                t2 = Thread(target=bruteForce, args=(hashList[i], target))
                t2.start()


if __name__ == "__main__":
    print(("\033[1;33m[***]\033[m \033[1;32m%s\033[m \
\033[1;34mv%.1f\033[m \033[1;37mWritten By\033[m \
\033[1;31m%s\033[m \033[1;33m[***]\033[m\n"
    % (__title__, __version__, __author__)))
    main()
