#!/bin/zsh

for i in {0..255}; do
  echo "====192.168.$1====";
  arp-scan -I eth1 192.168.$1.0/24 2>/dev/null | grep 192\\.168;
done
