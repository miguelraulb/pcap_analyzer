pcap_analyzer
-------------

Usage: pcap_analyzer.pl [OPTIONS] -f *pcap_file.pcap*

Options:

        -f -file - PCAP file to read
        -T -ftp - Get information about FTP requests and responses seen
        -P -http - Get information about HTTP requests seen
        -N -dns - Get matched pairs of DNS queries and answers
        -d -debug - Enables debugged output (for development use only)
        -h -? -help  - Prints this help

PCAP File:
Packet capture file to read. Must be a capture file generated previously with libpcap.

Basic Run example
-----------
```perl pcap_analyzer.pl -f capture.pcap```

Basic Output example
--------------------

############# TCP ##############
TCP total connection attempts: 456

TCP closed (total 123):
1.2.3.4.:80
1.2.3.4.:443
...

TCP open (total 100):
5.6.7.8:8080
5.6.7.8:9090
...

TCP filtered (total 10):
11.12.13.14:22
11.12.13.14:21
...

TCP Packets (total 1234):
10.10.10.10:5636 --> 20.20.20.20:53
50.50.50.50:5327 --> 127.0.0.1:3306

############# ICMP ##############
ICMP sources: 1.2.3.4, 5.6.7.8, 9.10.11.12,...

ICMP destinations: 127.0.0.1, 8.8.8.8

Most popular ICMP destination: 4.4.4.4 with 99 hits

ICMP Packets (total 509):
1.2.3.4:8 --> 8.8.8.8:8
8.8.8.8:11 --> 1.2.3.4:11
...

############# UDP ##############
UDP closed (total 1):
100.100.100.100:244

Extra Options example
---------------------
```perl pcap_analyzer.pl -f capture.pcap -T -N -P```

Extra Options Output example (similar as Basic Output but includes HTTP, FTP and DNS information)
-------------------------------------------------------------------------------------------------

############# FTP ##############
FTP total requests: 5

FTP total responses: 5

FTP total packets: 10

FTP Response: 8.8.8.8 -> 2.2.2.2: 220 ftp.server.org FTP server (vsftpd)
FTP Request: 2.2.2.2 -> 8.8.8.8: USER anonymous
FTP Response: 10.10.10.10 -> 2.2.2.2: 331 Please specify the password.
FTP Request: 2.2.2.2 -> 10.10.10.10: PASS user@example.com
...

############# HTTP ##############
HTTP total requests: 19

HTTP Request: 10.10.10.1 -> 200.200.200.200: GET / HTTP/1.0
HTTP Request: 10.10.10.1 -> 200.200.200.200:
HTTP Request: 10.10.10.1 -> 200.200.200.200: GET / HTTP/1.1
Host: webserver.net
User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14
Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
Accept-Language: en-us,en;q=0.5
Accept-Encoding: gzip,deflate
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
Keep-Alive: 300
Connection: keep-alive
....

############# DNS ##############

DNS total queries: 17

DNS total answers: 17

DNS matched queries and answers:

DNS Transaction ID: 0x1c8f
        Query: 172.16.20.30:32768 -> 8.8.4.4:53
        Answer: 8.8.4.4:53 -> 172.16.20.30:32768
...

Author
------

Miguel 'Mike' Bautista
© 2017
