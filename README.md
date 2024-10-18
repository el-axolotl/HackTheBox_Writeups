# Exploitation

## Password-Cracking Tools

The following list contains tools to assist you in your password-cracking, hash-cracking, and testing of credentials.

- CeWL: https://github.com/digininja/CeWL

    - A tool that can spider through a target website collecting unique and interesting words to turn into wordlists for password-crackers such as John The Ripper.

- Hashcat: https://github.com/hashcat/hashcat

    - Similar to John The Ripper, but is able to use multiple GPUs in parallel for password/hash cracking attacks.

- Hydra: https://github.com/braxtonculver/Hydra

    - Hydra is a tool that supports credential-testing of various network authentications.

- Mimikatz: https://github.com/gentilkiwi/mimikatz

    - Mimikatz is a tool used to extract plaintexts passwords, hashes, PIN codes and kerberos tickets from memory. It can also perform pass-the-hash, pass-the-ticket or build golden tickets.

- John The Ripper: https://github.com/openwall/john

    - John is a password-cracker available for many OS platforms.

## Web Application Attacks

- Improper handling of errors

    - Sometimes devs add code to help them debug at the time of development. Error codes can sometimes give more information about the environment, such as locations of files.

- Missing input validation or input sanitization

    - SQLi attacks.

        - To try this exploit, try entering a single quote character on forms or anywhere that the web app accepts user input. If the form outputs a SQL error, then you know that the web app is vulnerable to SQLi attacks.

        #### SQLi Example

        ```sql
        ' or 1=1;--
        ```

    - Directory traversal attacks

        - This attack takes place when you are able to access a file nested in a directory that you should not have access to. Web apps that allow for local or remote file inclusion can be susceptible to this attack is the input isn't being sanitized.

        #### Directory Traversal

        ```cmd
        http://localhost/../../Windows/system32/cmd.exe
        ``` 

        #### Encoded Directory Traversal

        ```cmd
        http://localhost/%2E%2E%2F%2E%2E%2FWindows/system32/cmd.exe
        ```

- A lack of code signing

    - Code and scripts can be signed using private and public certificates. If there is a lack of code signing, it means that the code can be altered with a possiblity of going undetected.

- Session attacks

    - Session highjacking

        - Session highjacking is done when another user's session token is used to impersonate that user (the victim).

    - Session replay

        - Session replay is when the attack has access to the authentication system, and the session is intercepted and repeated. A form of man-in-the-middle attack.

- Forgery attacks

    - Cross-site request forgery (CSRF/XSRF)

        - This type of attack is used to trick a victim user into making a request that they did not intend. Changing a password, settings, or any other unintended action would be an example. Exploiting an Administrator account with this type of attack could be catastrophic for the victim. The attack is carried out by crafting a URL with predefined variables in hopes that the victim doesn't notice. For example, creating a url that requests $100 to your attacker bank account, and sending out that url to a victim's email.

    - Server-side request forgery

        - This attack is similar to a CSRF attack, but the victim is the server itself. Once connected a server, you could have the server connect to other back-end systems in hopes of getting access to more information, credentials, etc.

- Cross-site scripting (XSS) attacks

    - 

### Resources

- OWASP Top 10 Application Security Risks: https://owasp.org/www-project-top-ten/

# Post Exploit

## Logs

### Clearing Logs

Once your attack is completed, it's important to remove any evidence that the attack took place. You can either erase whole log files or you can erase certain types of logs. Alternatively, you can modify timestamps to hinder and confuse forensic investigators.

- Windows

    - Metasploit's Meterpreter can run a command to clear all windows event logs: clearev

        - For more info: https://www.offsec.com/metasploit-unleashed/meterpreter-basics/#clearev

    - With the Windows CLI (CMD) you can clear log categories of your choosing. For instance, to clear the Security event logs: wevtutil cl Security

        - For more info: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil

- Linux

    - Use similar methods to clear any text file. To clear the syslog, try the following: echo "" > /var/log/syslog

    - Use the Stream Editor to remove specific log entries that may give clues about your attack. For instance, you log in by using an account named "backdoor", try wiping all entries from the auth.log file that may reveal this activity: sed -i "/backdoor/d" /var/log/auth.log

### Changing Logs

Why remove logs, when you could blame someone else?

- With some effort you could modify existing logs that track your attack, and modify them to blame someone else.

- Using Meterpreter's Incognito attack, you can steal another user's token and perform malicious tasks.

    - For more info: https://www.offsec.com/metasploit-unleashed/fun-incognito/

In both cases, the result will be logs from a different user taking malicious actions.

### Modify Timestamps

Simply modifying timestamps can help throw an investigation off your trail, however, it does confirm that some tampering did happen.

- Using Meterpreter's TimeStomp tool, you can change timestamp information on a log file's modification, access, created, and entry (MACE) metadata: 
    
    - meterpreter > timestomp log.txt -v

        - This command will change a file's MACE metadata to make it look like the file was modified, accessed, created, and entry data all at the same time

    - meterpreter > timestomp log.txt -m "10/31/1999 11:11:11"

        - This command will change a file's MACE metadata specifically to 10/31/1999 11:11:11
