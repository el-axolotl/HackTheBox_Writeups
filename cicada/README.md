# Cicada

URL: https://app.hackthebox.com/machines/Cicada

# Tools

- nmap
- nxc
- smbclient
- enum4linux
- evil-winrm
- SecretsDump.py

# Generic walk-through

Once HTB Season 6 has come to a close, I will update this walk-through with more detailed steps.

## Reconnaissance

### Scanning for open ports and services

- The first step in attempting to pwn any machine is to check for any open ports on that victim machine. A cli tool commonly used for this step is NMAP.

    - For more info on NMAP, checkout out: https://nmap.org/book/man.html

- With enough probing, you may discover the OS and a few interesting ports.

    - If you are unfamiliar with the ports discovered, checkout the following resource for explanations on the various ports discovered and what they could be used for: https://www.speedguide.net/ports.php?

    - Another resource to use when gathering intelligence, is to check CVE lists for ports and services identified on your victim machine, to learn about any documented volnurabilities: https://cve.mitre.org/cve/search_cve_list.html

### Scanning directories

- You may have found some open ports that point to the victim machine using the SMB protocol. As a first step, let's try accessing the SMB service anonymously with a cli tool.

    - For more info on SMB protocol, check out: https://learn.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview
    
- You'll notice there are some shares you have read permissions to as an anonymous user. We should dive deeper into these shares.

## Establishing a foothold

### Brute force

- Soon enough you will stumble across an email template from HR to new onboarded employees. This email template will contain the default password for new accounts. Let's make note of that default password as it will help us establish a foothold in the system.

    - As an optional step, I recommend storing that password into a default_pass.txt file to make our password spray attack a little easier for us, as many brute force tools allow for password files to enumerate through. In our case, our default_pass.txt should contain a single password to try.

- Now that we have a default password, we need to gather some usernames to try and brute force. The next step is to scan the SMB service again with our cli tool, but this time we'll enumerate users by bruteforcing RID. This will produce a list of domain users.

    - As an optional step, I recommend storing the bruteforce rid usernames into a usernames.txt file to make our password spray attack a little easier for us, as many brute force tools allow for username files to enumerate through. In our case, our usernames.txt should contain 5 usernames to try. 

- Next, we will try the same command we used on a previous step to connect to the SMB service anonymously, but this time for the username parameter we'll pass the username.txt file, and for the password parameter we'll pass the default_pass.txt file. This is our password spray attack ... and we're in!

    - This step will yield which username matches the default_pass.txt value. To avoid confusion in the next steps, I will refer to this username/password combination as User_A.

## Privilege escalation

The next few steps may feel repetative, but the point is to pivot, enumerate, and escalate our permissions until we can find our user flag.  

- Next, we will enumerate the domain users on the victim machine once more by continuing to exploit the SMB service, but with the credentials belonging to our User_A. The goal is to gather as much intelligence about the users and environment as possible.

- Enumerating the domain users as User_A reveals another interesting user object consisting of a username and description with their password.

    - To avoid confusion in the next steps, I will refer to this username/password combination as User_B.

- Once more we enumerate, but this time let's take a look at what shares User_B has access to.

- As we explore new directories, we find out that User_B is a DEV. Consequently, we find a powershell script, and under closer inspection of the code, we discover another username / password combo.

    - To avoid confusion in the next steps, I will refer to this username/password combination as User_C.

## Capturing the user flag

- Again we enumerate more shares, but now we'll authenticate as User_C. Many cli tools for enumerating shares contain optional parameters for pattern matching, sometimes refered to as 'spidering'. Let's look for txt files that might seem important.

- After a bit of enumerating, we should find a txt file on User_C's desktop with the user flag value to submit to HackTheBox. Congratulations! But we still have work to do to find the root flag.

## Capturing the root flag

- We navigate to C:\temp and locate the sam and system hive files and download them to our attack machine and use a tool to get the hashes out of those files.

- Finally, we use a tool to connect to the WINRM service this time as the Administrator and admin's hash instead of a password. The root flag can be found on the admin's desktop. 

# Additional resources

- Netexec: https://www.netexec.wiki/smb-protocol/enumeration

- Smbclient: https://commandmasters.com/commands/smbclient-linux/

- SMB Enumeration Cheatsheet: https://0xdf.gitlab.io/cheatsheets/smb-enum#

- How to use the command 'evil-winrm' (with examples): https://commandmasters.com/commands/evil-winrm-common/

- SecretsDump Demystified: https://medium.com/@benichmt1/secretsdump-demystified-bfd0f933dd9b
