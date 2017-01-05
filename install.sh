#!/bin/bash

echo "Installing extra CPAN modules for pcap_analyzer..."
cpan -i use Net::TcpDumpLog NetPacket::Ethernet NetPacket::IP NetPacket::TCP NetPacket::UDP NetPacket::ICMP;

if [ $? -eq 0 ]
then
  echo "Done!"
else
  echo "Error installing CPAN modules, try to run this script again"
fi
