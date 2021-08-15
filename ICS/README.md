# Industrial Control Systems

## Introductions
This are and folder is all about ICS stuff and things that I gather along the way for ICS testing and enumeration. Some might become visible later and some will remain private as I develop them.


## Reconnescenace
Looking for carrying out recon on the machines and find stuff that might be useful.
- [Recon and Scan the target](/offensive/initial_access.md)
- [Dealing with ICS Ports](#network-discovery)
- [Captured Some Wireshar, Now what?](#wireshark-searches-for-ics)

## Living of the Land
Sometimes you are doing an engagement and going into workstation or server and you have no tools or codes to actually give you access. [Living of the land](/ICS/lol.md) will give you some ideas where to start and binaries to use.


## Some magic tricks
If we know that our bridge ethernet `eth0` is connected to internet, we don't want that to connect to our client IP network. Therefore, we can have a USB interface and link it directly to the Kali virtual box to route the traffic directly to VM and not the Operating system.

- If you want to add our own IP address range within the network to get recognise, we do:
  `sudo ip addr add 192.168.0.2/24 dev eth1`
- or when we want to remove that Ip address
  `sudo ip addr del 192.168.0.2/24 dev eth1`

## Network Discovery:
1 - Start the wireshark and let it run in the background
2 - To understand the network and devices connected to it, we can run the command: `sudo arp-scan -I eth1 192.168.0.0/24`
  - Let's clean the output: `sudo arp-scan -I eth1 192.168.0.0/24 2>/dev/null | grep 192\\.168`
  - If we don't know the subnet that we are in [bash script here](/ICS/scripts/arp_scan_discovery.md):
    `for i in {0..5}; do echo "====192.168.$1===="; sudo arp-scan -I eth1 192.168.$1.0/24 2>/dev/null | grep 192\\.168; done`
3 - Then when we have the ip addresses we want to give ourselves an address:
  `sudo ip addr add 192.168.0.2/24 dev eth1`
4 - Then we can make a service discovery. becareful with nmap, we need to be cautious of nmap scanning PLCs. Usual ports can be flagged as `-p 21,22,23,80,102,443,502,8000,8008,8080,8443` if you want to be specific.
  `nmap -Pn -n -sT -p- $IP`


## Wireshark Searches for ICS
There are some samples [here in the link](https://github.com/ControlThings-io/ct-samples/tree/master/Protocols) that you can give it a try and try things out and see what the packets look like. Creating more custom searches based on what you want.
- Modbus Searches in Wireshark: `modbus`
- Tshark modbus: `tchark -Y 'modbus' -r plant1.pcap`
- Grab queires to understand server (dst) and clients (src) and sort them uniquly:
  `tshark -Y 'modbus && tcp.dstport == 502' -Tfields -e ip.src -e ip.dst -r plant1.pcap | sort -u`
- Or if you want to include vendor information
  `tshark -Y 'modbus && tcp.dstport == 502' -Tfields -e ip.src -e eth.src_resolved -e ip.dst -e eth.dst_resolved -r plant1.pcap`
