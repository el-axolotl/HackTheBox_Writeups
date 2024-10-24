# Beginners Guide To PermX

URL: https://app.hackthebox.com/machines/PermX

# Tools

- nmap

## Reconnaissance

### Scanning for open ports and services

- The first step in attempting to pwn any machine is to check for any open ports on that victim machine. A cli tool commonly used for this step is NMAP.

    - For more info on NMAP, checkout out: https://nmap.org/book/man.html

- With enough probing, you may discover the OS and a few interesting ports.

    - If you are unfamiliar with the ports discovered, checkout the following resource for explanations on the various ports discovered and what they could be used for: https://www.speedguide.net/ports.php?

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

