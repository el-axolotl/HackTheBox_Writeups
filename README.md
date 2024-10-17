# Post Exploit

## Logs

### Clearing Logs

Once your attack is completed, it's important to remove any evidence that the attack took place. You can either erase whole log files or you can erase certain types of logs. Alternatively, you can modify timestamps to hinder and confuse forensic investigators.

- Clearing Logs

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

        - This command will change a file's MACE metadata to make it look like the file was created, accessed, created, and modified all at the same time

    - meterpreter > timestomp log.txt -m "10/31/1999 11:11:11"

        - This command will change a file's MACE metadata specifically to 10/31/1999 11:11:11
