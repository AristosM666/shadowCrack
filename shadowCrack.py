#!/usr/bin/env python
#
# ~ Project: shadowCrack v1.0
# ~ Written By: AristosM666
#
##################################
from itertools import product
from threading import Thread
from sys import exit, argv
from crypt import crypt
import string


__author__ = "AristosM666"
__title__ = "shadowCrack"
__version__ = 1.0


def helpPage(status):
    print(("USAGE: %s [attack-opts] <target-opts>" % __title__))

    print("\nAttack-Opts:")
    print("\t-d <filename>    specify a dictionary file")
    print("\t-b, --brute      brute force provided hashes")
    print("\t-l, --list       list all users on the system and exit")
    print("\t-h, --help       display this help page and exit")

    print("\nTarget-Opts:")
    print("\t-t <target(s)>   specify a comma separated list of users to target")
    print("\t-f <filename>    specify a text file to read hashes from")
    print("\t-c <hash>        specify a hash to crack (deliminate '$' characters)")

    print("\nDescription:")
    print(("\t%s is a password cracker for *nix systems," % __title__))
    print("\tit will try to find hashed passwords or get them as user input")
    print("\tand then crack them using a dictionary and/or brute-force attack.")
    exit(status)


def errHandle(errno, fname):
    if "Errno 13" in str(errno):
        print(("[!] Error Permission Denied: Can\'t Open '%s'" % fname))
    elif "Errno 2" in str(errno):
        print(("[!] Error File not Found: Can\'t Find '%s'" % fname))
    else:
        print(("[!] Unknown Error while Opening File '%s'" % fname))
    print("[*] Aborting...")


def bruteForce(_hash, user):
    try:
        salt = "$" + _hash.split('$')[1] + "$" + _hash.split('$')[2]
    except:
        print("[!] Invalid Hash. (make sure to deliminate any '$' characters)")
        print("[*] Aborting...")
        exit(1)

    charSet = string.printable
    length = 1

    while True:
        gen = product(charSet, repeat=length)
        for word in gen:
            wordStr = ''.join(word).strip('\n')
            hashedWord = crypt(wordStr, salt)
            if hashedWord == _hash:
                if not user:
                    print(("\n[+] Hash Cracked: '%s'" % _hash))
                    print(("[~]     Password: '%s'" % wordStr))
                else:
                    print(("\n[+] Password for User '%s' Cracked!" % user))
                    print(("[~] Password: '%s'\n" % wordStr))
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
        print("[!] Invalid Hash. (make sure to deliminate any '$' characters)")
        print("[*] Aborting...")
        fdict.close()
        exit(1)

    for word in fdict.readlines():
        word = word.strip('\n')
        hashedWord = crypt(word, salt)
        if hashedWord == _hash:
            if not user:
                print(("\n[+] Hash Cracked: '%s'" % _hash))
                print(("[~]     Password: '%s'" % word))
            else:
                print(("\n[+] Password for User '%s' Cracked!" % user))
                print(("[~] Password: '%s'\n" % word))
            fdict.close()
            return

    if not user:
        print("[-] Unable to Crack User Provided Hash.")
    else:
        print(("[-] Password for '%s' Not Found!" % user))
    fdict.close()
    return


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
    listUsers = False
    brute = False
    targets = []
    userHash = ""
    dictionary = ""
    targetFile = ""

    i = 1
    while i < len(argv):
        if argv[i] == "-h" or argv[i] == "--help":
            helpPage(0)
        elif argv[i] == "-l" or argv[i] == "--list":
            listUsers = True
            break
        elif argv[i] == "-d":
            i += 1
            if i == len(argv):
                print("[!] Error No Value Specified for Option '-d'.\n")
                helpPage(1)
            dictionary = argv[i]
        elif argv[i] == "-t":
            i += 1
            if i == len(argv):
                print("[!] Error No Value Specified for Option '-t'.\n")
                helpPage(1)

            try:
                targets = (argv[i]).split(',')
            except:
                print(("[!] Error Invalid Value '%s' for Option '%s'.\n" % (argv[i], argv[i - 1])))
                helpPage(1)
        elif argv[i] == "-c":
            i += 1
            if i == len(argv):
                print("[!] Error No Value Specified for Option '-c'.\n")
                helpPage(1)
            userHash = argv[i]
        elif argv[i] == "-f":
            i += 1
            if i == len(argv):
                print("[!] Error No Value Specified for Option '-f'.\n")
                helpPage(1)
            targetFile = argv[i]
        elif argv[i] == "-b" or argv[i] == "--brute":
            brute = True
        else:
            print(("[!] Error Invalid Argument '%s'.\n" % argv[i]))
            helpPage(1)
        i += 1
    return listUsers, brute, dictionary, targets, userHash, targetFile


def main():
    PASS_FILES = ['/etc/shadow', '/etc/passwd']

    if not argv[1:]:
        helpPage(0)

    listUsers, brute, dictionary, targets, userHash, targetFile = getOpts()

    if listUsers:
        print("[*] Searching for Users...")
        for fname in PASS_FILES:
            targets, hashList = getTargets(fname)
            if targets:
                break

        if targets:
            print(("[+] %d User(s) Found." % len(targets)))
            print(("[+] %s" % ", ".join(map(str, targets))))
        exit(1)
    elif not dictionary and not brute:
        print("[-] No Dictionary File Specified.")
        print("[*] Aborting...")
        exit(1)
    elif not userHash and not targetFile and not targets:
        print("[-] No Targets or Hashes Specified.")
        print("[*] Aborting...")
        exit(1)

    if userHash:
        if dictionary:
            print("[*] Attempting Dictionary Attack Against Specified Hash...")
            t2 = Thread(target=dictionaryAttack, args=(userHash, None, dictionary))
            t2.start()

        if brute:
            print("[*] Brute Forcing Specified Hash...")
            t1 = Thread(target=bruteForce, args=(userHash, None))
            t1.start()

    if targetFile:
        print("[*] Reading Hashes From Specified File...")
        try:
            hashFile = open(targetFile, 'r')
        except Exception as err:
            errHandle(err, targetFile)

        for line in hashFile.readlines():
            _hash = line.split(':')[0].strip('\n')
            if '$' not in _hash:
                _hash = line.split(':')[1].strip('\n')
            print(("\n[~] %s" % _hash))

            if dictionary:
                print("[*] Attempting Dictionary Attack Against Specified Hash...")
                t1 = Thread(target=dictionaryAttack, args=(_hash, None, dictionary))
                t1.start()

            if brute:
                print("[*] Brute Forcing Specified Hash...")
                t2 = Thread(target=bruteForce, args=(_hash, None))
                t2.start()
        hashFile.close()

    if targets:
        print("[*] Searching for Users...")
        for fname in PASS_FILES:
            users, hashList = getTargets(fname)

            if not users:
                continue

            notFound = []
            for target in targets:
                for user in users:
                    if user == target:
                        print(("[+] User '%s' Found" % str(target)))
                        break
                else:
                    print(("[-] User '%s' Not Found" % str(target)))
                    notFound.append(target)

            for target in notFound:
                targets.remove(target)

            if targets:
                break

        if not targets or not users:
            print("\n[-] No Targets Found")
            print("[*] Aborting...")
            exit(1)

        print("\n[*] Attacking Specified User(s)...")

        for (i, target) in enumerate(targets):
            if dictionary:
                print(("[*] Attempting Dictionary Attack Against User '%s'" % target))
                t1 = Thread(target=dictionaryAttack, args=(hashList[i], target, dictionary))
                t1.start()

            if brute:
                print(("[*] Brute Forcing Password of User '%s'" % target))
                t2 = Thread(target=bruteForce, args=(hashList[i], target))
                t2.start()


if __name__ == "__main__":
    print(("[***] %s v%.1f Written By %s [***]\n"
    % (__title__, __version__, __author__)))
    main()
