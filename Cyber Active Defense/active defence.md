

Mitre Shield Website: https://shield.mitre.org/matrix/

Exercise #1 - XMRig
Known adversary tactics:
- Password guesses Apache tomcat and other web services
- Uses powershell as C2
- Scans 8080, 3306, 7001


Exercise #2 - Sunburst
Use Case: Detect Tactics used by Sunburst
Known adversary Tactics
- Unloads security software
- Enumerates Active Directory
- Queries targets for scheduled tasks
- Lateral Movement using WMI


# Encryption is the last stage of Ransomware

Before that:
- Establish a C2 Channel for remote control
- Attempt to persist incase access is lost
- Scan the environment to understand and find targets
- Escalate privileges and steal credentials for maximum impact
- Exfiltrate data to prove ransom demands
- Pre-encryption checks
- Encrypt Data

# Clarity on some Ransomware Concepts

- In domain authentication, you can have read/write privileges on file shares
- Write privileges != Command Execution privileges
- Administratior access on a machine is usually a default pre-requisite to run code
- With admin access, Ransomware can copy itself and execute code on a victim machine.
- Without admin access, Ransomeware can only infect files, folders and shares where it has write access.
