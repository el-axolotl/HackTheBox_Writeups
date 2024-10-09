# Cicada

URL: https://app.hackthebox.com/machines/Cicada

# Tools

- nmap
- nxc
- smbclient

# Generic walk-through

Once HTB Season 6 has come to a close, I will update this walk-through with more detailed steps.

## Reconnaissance

### Scanning for open ports and services

- The first step in attempting to pwn any machine is to check for any open ports on that victim machine. A tool commonly used for this step is NMAP.
    - For more info on NMAP, checkout out: https://nmap.org/book/man.html
- With enough probing, you may discover the OS and a few interesting ports.
    - If you are unfamiliar with the ports discovered, checkout the following resource for explanations on the various ports discovered and what they could be used for: https://www.speedguide.net/ports.php?
    - Another resource to use when gathering intelligence, is to check CVE lists for ports and services identified on your victim machine, to learn about any documented volnurabilities: https://cve.mitre.org/cve/search_cve_list.html

### Scanning directories

- You may have found some open ports that point to the victim machine using the SMB protocol. As a first step, let's try accessing the SMB service anonymously.
    - For more info on SMB protocol, check out: https://learn.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview
- You'll notice there are some shares you have read permissions to as an anonymous user. We should dive deeper into these shares.

## Establishing a foothold

### Brute force

- Soon enough you will stumble across an email template from HR to new onboarded employees. This email template will contain the default password for new accounts. Let's make note of that default password as it will help us establish a foothold in the system.
    - As an optional step, I recommend storing that password into a default_pass.txt file to make password spraying a little easier for us, as many brute force tools allow for password files to enumerate through. In our case, our default_pass.txt should contain a single password to try.
- Now that we have a password to try, we need to gather some usernames to try and brute force. The next logical step is to scan the SMB service again, but this time we'll check for users by bruteforcing RID.
    - As an optional step, I recommend storing the bruteforce rid usernames into a usernames.txt file to make password spraying a little easier for us, as many brute force tools allow for username files to enumerate through. In our case, our usernames.txt should contain 5 usernames to try. 
- Next, we will try the same command we previously used to connect to the SMB service anonymously, but this time for the username parameter we'll pass the username.txt file, and for the password parameter we'll pass the default_pass.txt file ... and we're in!

# Additional resources
- Netexec: https://www.netexec.wiki/smb-protocol/enumeration
- Smbclient: https://commandmasters.com/commands/smbclient-linux/
- SMB Enumeration Cheatsheet: https://0xdf.gitlab.io/cheatsheets/smb-enum#
