# OverTheWire Bandit — Write-Up

OTW:Bandit is a wargame that teaches Linux fundamentals and basic security/enumeration techniques entirely over SSH. Each level exposes a small puzzle and solving it reveals the password for the next level.

This write-up documents my approach through Levels 0–29.

Passwords are intentionally left out, in line with OverTheWire's fair-play norms — this document is meant to show technique, not answers.

Thank you to OverTheWire creators for the great exercises! For more information, check out: https://overthewire.org/wargames/

## Skills Demonstrated

- Linux CLI fluency (file discovery, permissions, process/job inspection)
- SUID binaries and privilege escalation primitives
- Cron job auditing and exploitation
- Basic cryptography (Base64, ROT13, layered compression formats)
- Networking tools (`nc`, `ncat`, `nmap`) and port/service enumeration
- Restricted-shell escapes
- Git internals (commit history as an attack surface)

---

## Level 0 -> 1
**Goal:** Establish the initial SSH connection to the game server.

```
ssh bandit0@bandit.labs.overthewire.org -p 2220 
```

## Level 1 -> 2
**Goal:** Locate and read a password file in the home directory.

```
ls ~  --- to check for the files in the home directory
cat readme  --- to open the file 
```

**WHY:** ls reveals what's in the home directory; cat prints the file.

## Level 2 -> 3
**Goal:** Read a file literally named -

```
cat ./-	 -- we specify the relative path of the file we want to open and read
```

**WHY:** A bare - is usually interpreted by commands as "read from stdin," not as a filename. Qualifying it with ./ forces it to be treated as a relative path instead.

## Level 3 -> 4
**Goal:** Read a file whose name contains spaces and leading dashes.

```
cat -- "--spaces in this filename--"  	  OR 	cat ./--spaces\ in\ this\ filename-- 	OR 	cat ./"--spaces in this filename--"
```

**WHY:** -- tells the command "no more flags follow," and quoting (or escaping) the spaces stops the shell from splitting the name into multiple arguments.

## Level 4 -> 5
**Goal:** Find a hidden file inside inhere/.

```
ls -a inhere/
cat inhere/...Hiding-From-You
```

**WHY:** ls -a shows dotfiles that a plain ls hides.

## Level 5 -> 6
**Goal:** Identify the one legitimate human-readable file among many decoys with misleading names.

```
find ./inhere/ -type f -exec file {} \; | grep -i "ascii"   --- had to find the only human readable file in the inhere directory.
cat ./inhere/-file07
```

**WHY:** A filename says nothing about its actual content. file inspects the real bytes (magic numbers) to classify each file, so filtering for "ASCII text" cuts through decoys instantly.

## Level 6 -> 7
**Goal:** Same idea as Level 5, narrowed by exact size and permission bits across many files.

```
find ./inhere/ -type f -size 1033c ! -executable -exec file {} \; | grep -i ascii  --- file which is not executable, of size 1033 bytes, and human readable
cat ./inhere/maybehere07/.file2
```

**WHY:** Stacking find filters (size, executable bit, then content type) narrows a large search space down to one candidate.

## Level 7 -> 8
**Goal:** Locate a file elsewhere on the filesystem using ownership metadata instead of a known path.

```
find / -user 'bandit7' -group 'bandit6' -size 33c -type f 2>/dev/null 		--- found file based off owner and group
```

**WHY:** find / with -user/-group/-size searches the entire filesystem by metadata, useful when you don't know or can't guess the path.

## Level 8 -> 9
**Goal:** Extract a value sitting next to a known keyword inside a large text file.

```
cat data.txt | grep -iE "*millionth*"   	--- password is next to the word 'millionth', so we search next to it
```

**WHY:** Regex filtering collapses a large file down to just the line(s) containing the marker word next to the value you need.

## Level 9 -> 10
**Goal:** Find the one line in a file that has no duplicates.

```
cat data.txt | sort | uniq -u 		--- to find the only unique line of text. 'uniq -u' will find unqiue lines, uniq alone won't
```

**WHY:** sort groups identical lines together; uniq -u then prints only the lines that appear exactly once, isolating the odd one out.

## Level 10 -> 11
**Goal:** Pull a readable, encoded string out of a file that's mostly binary noise.

```
cat data.txt | strings | grep -E "(==)+" 	--- found the human readable strings, and found the lines that contain several = symbols
```

**WHY:** strings extracts printable text from any file regardless of format, and Base64's = padding is a reliable marker to grep for.

## Level 11 -> 12
**Goal:** Decode a Base64-encoded value.

```
base64 -d data.txt	-- the file is only base 64 encoded, so we decode
```

**WHY:** Base64 is an encoding, not encryption -- directly reversible with the standard tool.

## Level 12 -> 13
**Goal:** Reverse a ROT13 substitution cipher.

```
cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m' 	OR 	  tr 'A-Za-z' 'N-ZA-Mn-za-m' < data.txt		--- to solve this a simple google search does the job; ROT13 cipher
```

**WHY:** ROT13 shifts each letter 13 places through the alphabet; applying the identical shift a second time returns it to plaintext, which tr can do character-by-character.

## Level 13 -> 14
**Goal:** Unwrap a file that's been layered through several different compression/encoding formats.

```
    1  mktemp -d
    2  cd /tmp/tmp.U7sHdakOL1
    3  cp ~/data.txt ./lo.txt
    4  ls
    5  file lo.txt 
    6  xxd -r lo.txt > km.txt
    7  file km.txt 
    8  mv km.txt km.txt.gz && gzip -d km.txt.gz 
    9  file km.txt 
   10  mv km.txt km.txt.bz2 && bzip2 -d km.txt.bz2
   11  file km.txt 
   12  mv km.txt km.txt.gz && gzip -d km.txt.gz && file km.txt
   13  mv km.txt km.txt.tar && tar -tvf km.txt.tar 
   14  tar -xvf km.txt.tar && file data5.bin
   15  mv data5.bin data5.bin.tar
   16  tar -tvf data5.bin.tar && tar -xvf data5.bin.tar 
   17  file data6.bin 
   18  mv data6.bin data6.bin.bz2 && bzip2 -d data6.bin.bz2 
   19  file data6.bin 
   20  mv data6.bin data6.bin.tar && tar -tvf data6.bin.tar
   21  tar -xvf data6.bin.tar && file data8.bin
   22  mv data8.bin data8.bin.gz && gzip -d data8.bin.gz && file data8.bin
   23  cat data8.bin

hexdump = xxd
```

**WHY:** file tells you the current layer's real format regardless of file extension, so we iteratively rename-and-decompress until we reach plain text.

## Level 14 -> 15
**Goal:** Use a retrieved private SSH key to authenticate as the next user, instead of a password.

```
scp -P 2220 bandit13@bandit.labs.overthewire.org:/home/bandit13/sshkey.private /home/noel/Desktop/OTW/key.txt
chmod 600 /home/noel/Desktop/OTW/key.txt
ssh -i /home/noel/Desktop/OTW/key.txt bandit14@bandit.labs.overthewire.org -p 2220
```

**WHY:** SSH key-based auth needs a private key with restrictive permissions (600) -- SSH refuses to use an over-permissioned key file.

## Level 15 -> 16
**Goal:** Submit a password to a local TCP service to receive the next one.

```
cat /etc/bandit_pass/bandit14
nc 127.0.0.1 30000	--- connected to local host on port 30000, then submitted the password of bandit14 to retreive the flag
```

**WHY:** nc (netcat) opens a raw TCP connection, letting you talk to a listening service directly without a dedicated client.

## Level 16 -> 17
**Goal:** Same idea, but the service only accepts TLS connections.

```
ncat --ssl 127.0.0.1 30001
```

**WHY:** Plain nc is rejected by an SSL-only listener; ncat --ssl performs the TLS handshake that netcat alone can't.

## Level 17 -> 18
**Goal:** Find which port, out of a wide range, is actually running the target service.

```
nmap -p31000-32000 127.0.0.1
ncat --ssl 127.0.0.1 31790	--- attempt to connect to the ports found, and if they support ssl then the connection will be successful
	OR
nmap -sV -p31000-32000 127.0.0.1 -- to find the ssl port automatically (skips checking manually)
```

**WHY:** nmap's service/version detection identifies which open port is actually speaking SSL, instead of testing each one by hand.

## Level 18 -> 19
**Goal:** Spot the one changed line between two similar files.

```
diff passwords.new passwords.old  --- compare the files content and see where they differ
```

**WHY:** diff highlights exactly what differs between two files line-by-line -- immediately surfacing the changed password.

## Level 19 -> 20
**Goal:** Run a command on a server whose login shell would otherwise disconnect you immediately.

```
ssh bandit18@bandit.labs.overthewire.org -p 2220 -o RemoteCommand="ls"
ssh bandit18@bandit.labs.overthewire.org -p 2220 -o RemoteCommand="cat readme"
	OR
ssh bandit18@bandit.labs.overthewire.org -p 2220 "ls"
ssh bandit18@bandit.labs.overthewire.org -p 2220 "cat readme"
```

**WHY:** Passing a command directly to ssh executes it non-interactively, before a restrictive login shell gets a chance to end the session.

## Level 20 -> 21
**Goal:** Read a file you don't have direct permission to access.

```
./bandit20-do cat /etc/bandit_pass/bandit20	--- SUID is set, so we execute the script with the privileges of bandit20
```

**WHY:** A SUID-root binary runs with its owner's privileges no matter who executes it -- calling it lets you read files that account owns.

## Level 21 -> 22
**Goal:** Use a provided client program that only relays data to a listener you control.

```
tmux
ctrl + b + "
---1st window---> nc -l 127.0.0.1 40001
		  paste the passwd of previous level
---2nd window---> ./suconnect 40001 (btw port number value was chosen at random, just pick one that is not in use)
```

**WHY:** Splitting a tmux session lets you run a listener and the client side-by-side, so the password can be relayed between them on a port you choose.

## Level 22 -> 23
**Goal:** Find a password that's written out by a scheduled task rather than sitting in a static file.

```
ls -a -l /etc/cron.d/
cat /etc/cron.d/cronjob_bandit22
cat /usr/bin/cronjob_bandit22.sh
cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv   --- following the trails found
```

**WHY:** Cron jobs in /etc/cron.d/ and their target scripts show exactly what a privileged, scheduled process does -- including where it writes secrets.

## Level 23 -> 24
**Goal:** Exploit a cron script that derives its output filename from a username hash.

```
cat /etc/cron.d/cronjob_bandit23
cat /usr/bin/cronjob_bandit23.sh
echo I am user bandit23 | md5sum | cut -d ' ' -f 1	--- modified the script to add bandit23 instead of the $whoami
cat /tmp/8ca319486bfbbc3663ea0fbe81326349 	--- open the dir where the passwd was stored
```

**WHY:** Reading the script reveals it names its output file after md5sum of the username running it. Reproducing that formula for the target user predicts the exact filename it wrote to.

## Level 24 -> 25
**Goal:** Get a script executed automatically by cron, as a higher-privileged user.

Idea: read the script, and see that there is a directory where you have write and execute permissions. You have to put your script in that directory and wait for cron to execute it. Remember to give execute permissions to the script file. One way to do it is by using ncat and tmux. To send a file: `ncat IP PORT < file/to/send`. To retreive a file: `ncat -l IP PORT > /where/to/save/file`. Other method (simpler): `cat /etc/bandit_pass/bandit24 > /tmp/tmp.OKSvwedyUp/ans.txt` -- just make sure that the process (eg. bandit24) has write permissions, otherwise the script will fail.

**WHY:** Anything placed in a world-writable directory that cron executes on a schedule runs with that job's privileges -- a classic privilege-escalation primitive.

## Level 25 -> 26
**Goal:** Brute-force a 4-digit numeric PIN against a listening service.

I used this script:
```bash
#!/bin/bash

a=0
while [ $a -lt 10 ]
do
	b=0
	while [ $b -lt 10 ]
	do
		c=0
		while [ $c -lt 10 ]
		do
			d=0
			while [ $d -lt 10 ]
			do
				echo "PASSWD OF PREV. LEVEL" "$a$b$c$d"
				((d++))
			done
			((c++))
		done
		((b++))
	done
	((a++))
done
```

**WHY:** A 4-digit keyspace (0000-9999) is small enough to brute-force outright with simple nested loops.

## Level 26 -> 27
**Goal:** Escape a restricted, non-standard login shell.

Idea here:
1. Open /etc/passwd file, grep bandit26 and follow trails --- this is from bandit 25.
2. Try to ssh to bandit26. Resize the shell window so that more works - if 'more' can fit the entire text of the file, then the --More-- option will not show. So, make the window size small enough just to trigger that --More-- option, then press 'h' for help and read the help menu - you will see that if you press 'v' you can open vi. Within vi, to check the current shell type `:set shell?`, to change the shell `:set shell=/bin/bash` (or other shell). To open a shell within vi, type `:shell`, and boom you finally have an interactive shell.

Worth noting: You can execute shell commands within the 'more' pager, just by pressing `!<command>` --- in this case, because the shell was a script and not an actual shell, we could not run any commands. To solve that, we had to change the shell first, and then open the interactive shell.

**WHY:** Resizing the terminal forces the more pager to paginate. Its built-in v command opens vi, and vi's :shell drops you into a real interactive shell -- bypassing the restricted one entirely.

## Level 27 -> 28
**Goal:** Run a SUID helper despite having an unusual, non-standard default shell.

Here all we have to do is run the script. `ls -l` will reveal that the bandit27-do file has it's SUID bit set, therefore we can execute the script with the permissions of it's owner (bandit27 in this case). To run it, use `./bandit27-do`. Other methods won't work bc the shell for bandit27 is not a proper shell like bash, sh, or zsh, so just use the above method.

**WHY:** Calling the SUID binary directly still executes it with the file owner's privileges, regardless of what your own login shell is.

## Level 28 -> 29
**Goal:** Retrieve a secret from a git repository's history, not its current files.

```
git clone ssh://bandit27-git@bandit.labs.overthewire.org:2220/home/bandit27-git/repo ./  	--- cloned a git repo
```

**WHY:** Cloning gives you the full commit history, which can still contain sensitive data even if the latest commit looks clean.

## Level 29 -> 30
**Goal:** Inspect a specific past commit to recover data that was removed later.

```
git log  -- to view the history of commits
git show <commit-id> -- to see the details of a specific commit
```

**WHY:** git log and git show expose the exact state and diff of any historical commit -- deleting a file in a later commit doesn't erase it from history.
