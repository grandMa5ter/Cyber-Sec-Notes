

Mitre Shield Website: https://shield.mitre.org/matrix/

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
- Administrator access on a machine is usually a default pre-requisite to run code
- With admin access, Ransomware can copy itself and execute code on a victim machine.
- Without admin access, Ransomware can only infect files, folders and shares where it has write access.
