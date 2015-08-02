if [ "$EUID" -ne 0 ]
then
	echo "[-] Run as root to Install"
	exit
fi

{ 
	cp shadowCrack.py /usr/bin/shadowCrack && 
	echo "[+] Moved Script to '/usr/bin'"
} || {
  echo "[-] Failed to Move Script to '/usr/bin'"
	exit
}

{
	chmod 755 /usr/bin/shadowCrack && 
	echo "[+] Changed File Permissions of Script"
} || {
	echo "[-] Failed to Change File Permissions of Script"
	exit
}


echo -e "[+] shadowCrack Installed Successfully\n"
shadowCrack
