# H1 pcap_analyzer

Usage: pcap_analyzer.pl [OPTIONS] -f *pcap_file.pcap*

Options:

        -f -file - PCAP file to read
        -T -ftp - Get information about FTP requests and responses seen
        -P -http - Get information about HTTP requests seen
        -N -dns - Get matched pairs of DNS queries and answers
        -X -extra - Extra information
        -d -debug - Enables debugged output (for development use only)
        -h -? -help  - Prints this help

PCAP File:
Packet capture file to read. Must be a capture file generated previously with libpcap.
