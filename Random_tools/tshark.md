# General Tshark:

# Tshark Useful Commands:

- all Tshark net interf for monitoring:
 `tshark -D`
- sniff on the interface:
 `tshark -i eth0`
- packet count in a tshark:
 `tshark -r *.pcap | wc -l`
- Protocol Types in file:
 `tshark -r *file_name -z ptype, tree -q`
- capturing protocol types by detail of packets:
 `tshark -r *.pcap -T fields -e frame.protocols | sort -bgr | uniq -c | sort -bgr`
- Parse User Agents and Frequency
 `tshark -r example.pcap -Y http.request -T fields -e http.host -e http.user_agent | sort | uniq -c | sort -n`
- Extracts both the DNS query and the response address
 `tshark -i wlan0 -f "src port 53" -n -T fields -e dns.qry.name -e dns.resp.addr`

# HTTP filtering:

- Showing only the HTTP traffic:
- `tshark -Y ‘http’ -r *.pcap`
- Showing only the HTTP traffic statistics:
- `tshark -r *.pcap -z http,tree -q`
- HTTP traffic isolation between a source and destination:
- `tshark -r *.pcap -Y "ip.src==192.168.252.128 && ip.dst==52.32.74.91"`
- HTTP packets that only contain GET request:
- `tshark -r *.pcap -Y "http.request.method==GET"`
- Command can be used to print only source IP and URL for all GET request packets
- `tshark -r HTTP_traffic.pcap -Y "http.request.method==GET" -Tfields -e frame.time -e ip.src -e http.request.full_uri`
- How many packets contain “password”
- `tshark -r HTTP_traffic.pcap -Y "http contains password”`
- `tshark -i wlan0 -Y 'http.request.method == POST and tcp contains "password"' | grep password`
- Which IP address was sent GET requests for www.***.com?
- `tshark -r HTTP_traffic.pcap -Y "http.request.method==GET && http.host==www.***.com" -Tfields -e ip.dst`
- What is the session ID being used by 192.168.252.128 for **##?
- `tshark -r HTTP_traffic.pcap -Y "ip contains **## && ip.src==192.168.252.128" -Tfields -e ip.src -e http.cookie`
- What type of OS the machine on IP address 192.168.252.128 is using??
- `tshark -r HTTP_traffic.pcap -Y "ip.src==192.168.252.128 && http" -Tfields -e http.user_agent`


# HTTPS traffic filtering:

- Which command can be used to only show SSL traffic?
- `tshark -Y ‘ssl’ -r HTTPS_traffic.pcap`
- Command can be used to only print the source IP and destination IP for all SSL handshake packets
- `tshark -r HTTPS_traffic.pcap -Y "ssl.handshake" -Tfields -e ip.src -e ip.dst`
- What command can be used to list issuer name for all SSL certificates exchanged?
- `tshark -r HTTPS_traffic.pcap -Y "ssl.handshake.certificate" -Tfields -e x509sat.printableString`
- What command can be used to print the IP addresses of all servers accessed over SSL?
- `tshark -r HTTPS_traffic.pcap -Y "ssl && ssl.handshake.type==1" -Tfields -e ip.dst`
- What DNS servers were used by the clients for domain name resolutions?
- `tshark -r HTTPS_traffic.pcap -Y "dns && dns.flags.response==0" -Tfields -e ip.dst`
- If you want to get unique results: pipe it through with this == sort | uniq
- Some machines have a popular antivirus software running on them. What is the name of the antivirus solution? What are the IP addresses of the machines running this solution?
- `tshark -r HTTPS_traffic.pcap -Y "ip contains avast" -Tfields -e ip.src`
