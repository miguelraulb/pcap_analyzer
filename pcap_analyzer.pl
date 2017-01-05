#!/usr/bin/perl

use strict;
use warnings;

use lib './NetPacket/';
use Getopt::Long qw(GetOptions);

use Net::TcpDumpLog;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use NetPacket::UDP;
use ICMP;

my $file	= "";
my $ftp_info	= "";
my $http_info	= "";
my $dns_info	= "";
my $extra_info	= "";
my $debug	= "";

sub help(){
	print "
Usage: $0 [OPTIONS] -f <pcap_file.pcap>

Options:

	-f -file - PCAP file to read
	-T -ftp - Get information about FTP requests and responses seen
	-P -http - Get information about HTTP requests seen
	-N -dns - Get matched pairs of DNS queries and answers
	-d -debug - Enables debugged output (for development use only)
	-h -? -help  - Prints this help

PCAP File:
Packet capture file to read. Must be a capture file generated previously with libpcap.

";
}

sub print_tcp_results{
	my ($tcp_attempts,%tcp_open,@tcp_total,%tcp_closed,%tcp_filtered);

	$tcp_attempts = shift;
	%tcp_open = %{shift()};
	@tcp_total = @{shift()};
	%tcp_closed = %{shift()};
	%tcp_filtered = %{shift()};

	my $total_tcp_open = 0;
	my $total_tcp_packets = 0;
	my $total_tcp_closed = 0;
	my $total_tcp_filtered = 0;
	my %tmp_filtered_ports = ();
	print "############# TCP ##############\n";

	#Print TCP total connection attempts
	print "TCP total connection attempts: $tcp_attempts\n";

	#Format TCP closed ports
	foreach my $closed_port (keys %tcp_closed){
		print "[DEBUG] Found IP address with closed port: $closed_port\n" if $debug && $tcp_closed{$closed_port} == 2; #This value should be 1717 instead of 1695 as per wireshark
		$total_tcp_closed++ if $tcp_closed{$closed_port} == 2;
	}

	#Print TCP closed ports
	print "\nTCP closed (total ".($total_tcp_closed)."):\n";
	foreach my $closed_port (keys %tcp_closed){
		if($closed_port =~ /(.*)\_(.*)\:(.*)/m){
			print "$2:$3\n" if $tcp_closed{$closed_port} == 2;
		}
	}

	#Format TCP open ports
	foreach my $open_port (keys %tcp_open){
		print "[DEBUG] Found IP address with open port: $open_port\n" if $debug && $tcp_open{$open_port} == 2;
		$total_tcp_open++ if $tcp_open{$open_port} == 2;
	}

	#Print TCP open ports
	print "\nTCP open (total ".($total_tcp_open)."):\n";
	foreach my $open_port (keys %tcp_open){
		if($open_port =~ /(.*)\_(.*)\:(.*)/m){
			print "$2:$3\n" if $tcp_open{$open_port} == 2;
		}
	}

	#Format TCP filtered ports
	foreach my $filtered_port (keys %tcp_filtered){
		print "[DEBUG] Found IP address with filtered port: $filtered_port\n" if $debug && $tcp_filtered{$filtered_port} == 2;
		if($tcp_filtered{$filtered_port} == 2){
			if($filtered_port =~ /(.*)\_(.*)/m){
				$tmp_filtered_ports{"$2"}++;
			}
		}
	}

	#Print TCP filtered ports
	$total_tcp_filtered = keys %tmp_filtered_ports;
	print "\nTCP filtered (total $total_tcp_filtered):\n";
	foreach my $filtered_port (keys %tmp_filtered_ports){
			print "$filtered_port\n";
	}

	#Format total TCP packets
	for my $tcp_packet (@tcp_total){
		$total_tcp_packets++;
	}

	#Print total TCP Packets
	print "\nTCP Packets (total $total_tcp_packets):\n";
	for my $tcp_packet (@tcp_total){
		print "$tcp_packet\n";
	}
}

sub print_udp_results{
	my %udp_closed = %{shift()};
	my $total_udp_closed = keys %udp_closed;

	print "\n############# UDP ##############\n";
	print "UDP closed (total $total_udp_closed):\n";

	foreach my $closed_port (keys %udp_closed){
		print "$closed_port\n";
	}
}

sub print_icmp_results{
	my (%icmp_source,%icmp_destination,@icmp_total);

	%icmp_source = %{shift()};
	%icmp_destination = %{shift()};
	@icmp_total = @{shift()};

	print "\n############# ICMP ##############\n";
	print "ICMP sources: ";
	my $total_source = keys %icmp_source;
	foreach my $source (keys %icmp_source){
		print "$source";
		if ( 0 < --$total_source ){
			print ", ";
		}
		else{
			print "\n";
		}
	}

	print "\nICMP destinations: ";
	my $total_destination = keys %icmp_destination;
	foreach my $destination (keys %icmp_destination){
		print "$destination";
		if ( 0 < --$total_destination ){
			print ", ";
		}
		else{
			print "\n";
		}
	}

	print "\nMost popular ICMP destination: ";
	foreach my $popular (sort keys %icmp_destination){
		print "$popular with $icmp_destination{$popular} hits\n";
		last;
	}

	#Print total TCP Packets
	my $icmp_total_count = @icmp_total;
	print "\nICMP Packets (total $icmp_total_count):\n";
	for my $icmp_packet (@icmp_total){
		print "$icmp_packet\n";
	}
}

sub print_ftp_results{
	my (@ftp_packets,$ftp_count_request,$ftp_count_response);

	@ftp_packets = @{shift()};
	$ftp_count_request = shift;
	$ftp_count_response = shift;

	my $ftp_total_packets = $ftp_count_response + $ftp_count_request;

	print "\n############# FTP ##############\n";
	print "FTP total requests: $ftp_count_request\n\n";
	print "FTP total responses: $ftp_count_response\n\n";
	print "FTP total packets: $ftp_total_packets\n\n";
	for my $ftp_packet (@ftp_packets){
		print "$ftp_packet";
	}
}

sub print_http_results{
	my (@http_packets,$http_count_request);

	@http_packets = @{shift()};
	$http_count_request = shift;

	print "\n############# HTTP ##############\n";
	print "HTTP total requests: $http_count_request\n\n";
	for my $http_packet (@http_packets){
		print "$http_packet";
	}
}

sub print_dns_results{
	my (%dns_packets,$dns_count_query,$dns_count_answer);

	%dns_packets = %{shift()};
	$dns_count_query = shift;
	$dns_count_answer = shift;

	print "\n############# DNS ##############\n";
	print "\nDNS total queries: $dns_count_query\n";
	print "\nDNS total answers: $dns_count_answer\n";
	print "\nDNS matched queries and answers:\n\n";

	foreach my $dns_packet (keys %dns_packets){
		if($dns_packet =~ /(.*)\_(.*)\_(.*)/m && $dns_packets{$dns_packet} == 2){
			print "DNS Transaction ID: $3\n";
			print "\tQuery: $1 -> $2\n";
			print "\tAnswer: $2 -> $1\n\n";
		}
	}

	print "\nDNS single queries or answers:\n\n";

	foreach my $dns_packet (keys %dns_packets){
		if($dns_packet =~ /(.*)\_(.*)\_(.*)/m && $dns_packets{$dns_packet} == 1){
			print "DNS Transaction ID: $3\n";
			print "\tQuery/Answer: $1 -> $2\n\n" ;
		}
	}
}

sub main(){
	my $pcap_file = Net::TcpDumpLog->new();

	my $tcp_attempts = 0;
	my %tcp_open;
	my %tcp_filtered;
	my %tcp_closed;
	my @tcp_total;

	my %icmp_source;
	my %icmp_destination;

	my @icmp_total;

	my %udp_closed;

	my @ftp_packets;
	my $ftp_count_request = 0;
	my $ftp_count_response = 0;

	my @http_packets;
	my $http_count_request = 0;

	my %dns_packets;
	my $dns_count_query = 0;
	my $dns_count_answer = 0;

	help() if @ARGV == 0;

	GetOptions(
		'file|f=s'	=> \$file,
		'ftp|T'		=> \$ftp_info,
		'http|P'	=> \$http_info,
		'dns|N'		=> \$dns_info,
		'extra|X'	=> \$extra_info,
		'debug|d'	=> \$debug,
		'help|?|h'	=> \&help
	) || die help();

	exit if !$file;

	print "[DEBUG] Using PCAP file: $file\n" if $debug;
	$pcap_file->read($file);

	foreach my $index ($pcap_file->indexes){
		my $data = $pcap_file->data($index);

		my $eth_obj = NetPacket::Ethernet->decode($data);
		next unless $eth_obj->{type} == NetPacket::Ethernet::ETH_TYPE_IP;

		my $ip_obj = NetPacket::IP->decode($eth_obj->{data});

		#Analyze TCP Packets
		if ($ip_obj->{proto} == NetPacket::IP::IP_PROTO_TCP){
			my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
			#Search for total TCP packets
			push @tcp_total,"$ip_obj->{src_ip}:$tcp_obj->{src_port} --> $ip_obj->{dest_ip}:$tcp_obj->{dest_port}";
			#Search for connection attempts
			if ($tcp_obj->{flags}==0x02){
				print "[DEBUG] Connection attempt packet: $ip_obj->{src_ip}:$tcp_obj->{src_port}->$ip_obj->{dest_ip}:$tcp_obj->{dest_port} with TCP Flags 0x02\n" if $debug;
				$tcp_attempts++;
			}
			#Search for open ports by verifying both SYN and SYN-ACK packets belonging to a same socket
			if ($tcp_obj->{flags} == 0x02){
				$tcp_open{"$ip_obj->{src_ip}:$tcp_obj->{src_port}_$ip_obj->{dest_ip}:$tcp_obj->{dest_port}"}++;
			}
			if ($tcp_obj->{flags} == 0x12){
				$tcp_open{"$ip_obj->{dest_ip}:$tcp_obj->{dest_port}_$ip_obj->{src_ip}:$tcp_obj->{src_port}"}++;
			}
			#Search for closed ports by verifying both SYN and RST-ACK packets belonging to a same socket
			if ($tcp_obj->{flags} == 0x02){
				$tcp_closed{"$ip_obj->{src_ip}:$tcp_obj->{src_port}_$ip_obj->{dest_ip}:$tcp_obj->{dest_port}"}++;
			}
			if ($tcp_obj->{flags} == 0x14){
				$tcp_closed{"$ip_obj->{dest_ip}:$tcp_obj->{dest_port}_$ip_obj->{src_ip}:$tcp_obj->{src_port}"}++;
			}
			if ($tcp_obj->{flags} == 0x04){
				$tcp_closed{"$ip_obj->{dest_ip}:$tcp_obj->{dest_port}_$ip_obj->{src_ip}:$tcp_obj->{src_port}"}++;
			}
			#Search for filtered ports by verifying 2 SYN packets with same L3 info but source port increased on 1
			if ($tcp_obj->{flags} == 0x02){
				$tcp_filtered{"$ip_obj->{src_ip}:$tcp_obj->{src_port}_$ip_obj->{dest_ip}:$tcp_obj->{dest_port}"}++;
			}
			if ($tcp_obj->{flags} == 0x02){
				my $tmp_filtered_port = $tcp_obj->{src_port} - 1;
				$tcp_filtered{"$ip_obj->{src_ip}:"."$tmp_filtered_port"."_$ip_obj->{dest_ip}:$tcp_obj->{dest_port}"}++;
			}
		}#End of TCP analysis

		#Analyze UDP Packets
		if ($ip_obj->{proto} == NetPacket::IP::IP_PROTO_ICMP){
			my $icmp_obj = NetPacket::ICMP->decode($ip_obj->{data});
			#Search for both ICMP type and code 3 which is port unreachable on UDP or port closed.
			if($icmp_obj->{type} == 3 and $icmp_obj->{code} == 3){
				print "[DEBUG] ICMP unreachable packet: $ip_obj->{src_ip} -> $ip_obj->{dest_ip}\n" if $debug;
				#Search for the internal embedded packet into the ICMP unreachable packet
				my $ip_packet = NetPacket::IP->decode($icmp_obj->{data});
				my $udp_packet = NetPacket::UDP->decode($ip_packet->{data});
				print "\t[DEBUG] Found IP address with UDP port closed: $ip_packet->{src_ip}:$udp_packet->{src_port} -> $ip_packet->{dest_ip}:$udp_packet->{dest_port}\n" if $debug;
				#Original sent packet that triggered the ICMP port unreachable packet
				$udp_closed{"$ip_packet->{dest_ip}:$udp_packet->{dest_port}"}++;
			}
		}#End of UDP analysis

		#Analyze ICMP Packets
		if ($ip_obj->{proto} == NetPacket::IP::IP_PROTO_ICMP){
			my $icmp_obj = NetPacket::ICMP->decode($ip_obj->{data});
			#Search for ICMP source packets
			print "[DEBUG] ICMP source packet: $ip_obj->{src_ip}\n" if $debug;
			$icmp_source{"$ip_obj->{src_ip}"}++;
			#Search for ICMP destination packets
			print "[DEBUG] ICMP destination packet: $ip_obj->{dest_ip}\n" if $debug;
			$icmp_destination{"$ip_obj->{dest_ip}"}++;
			#Search for total ICMP packets
			print "[DEBUG] ICMP packets: $ip_obj->{src_ip}:$icmp_obj->{type} --> $ip_obj->{dest_ip}:$icmp_obj->{type} \n" if $debug;
			push @icmp_total,"$ip_obj->{src_ip}:$icmp_obj->{type} --> $ip_obj->{dest_ip}:$icmp_obj->{type}";
		}#End of ICMP analysis

		#Analyze FTP Packets
		if($ftp_info){
			if ($ip_obj->{proto} == NetPacket::IP::IP_PROTO_TCP){
				my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
				if ($tcp_obj->{dest_port} == 21 and $tcp_obj->{data}){
					my $ftp_request = NetPacket::TCP::strip($ip_obj->{data});
					$ftp_count_request++;
					push @ftp_packets,"FTP Request: $ip_obj->{src_ip} -> $ip_obj->{dest_ip}: $ftp_request";
					print "[DEBUG] FTP Request: $ip_obj->{src_ip} -> $ip_obj->{dest_ip}: $ftp_request\n" if $debug;
				}
				if ($tcp_obj->{src_port} == 21 and $tcp_obj->{data}){
					my $ftp_response = NetPacket::TCP::strip($ip_obj->{data});
					$ftp_count_response++;
					push @ftp_packets,"FTP Response: $ip_obj->{src_ip} -> $ip_obj->{dest_ip}: $ftp_response";
					print "[DEBUG] FTP Response: $ip_obj->{src_ip} -> $ip_obj->{dest_ip}: $ftp_response\n" if $debug;
				}
			}
		}#End of FTP analysis

		#Analyze HTTP Packets
		if($http_info){
			if ($ip_obj->{proto} == NetPacket::IP::IP_PROTO_TCP){
				my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
				if ($tcp_obj->{dest_port} == 80 and $tcp_obj->{data}){
					my $http_request = NetPacket::TCP::strip($ip_obj->{data});
					$http_count_request++;
					push @http_packets,"HTTP Request: $ip_obj->{src_ip} -> $ip_obj->{dest_ip}: $http_request";
					print "[DEBUG] HTTP Request: $ip_obj->{src_ip} -> $ip_obj->{dest_ip}: $http_request\n" if $debug;
				}
			}
		}#End of FTP analysis

		#Analyze DNS Packets
		if($dns_info){
			if ($ip_obj->{proto} == NetPacket::IP::IP_PROTO_UDP){
				my $udp_obj = NetPacket::UDP->decode($ip_obj->{data});
				#DNS queries
				if ($udp_obj->{dest_port} == 53 and $udp_obj->{data}){
					my $dns_raw_data = NetPacket::UDP::strip($ip_obj->{data});
					my $transaction_id = unpack('H*', substr($dns_raw_data,0,2));
					#Better not to print queries since due to the raw data extracted from the packet, there are non-ASCII chars
					#That doesn't allow a better handling of the string and make it look formatted better.
					#my $query = unpack('A*', substr($dns_raw_data,12)); #Extracts queries from DNS data
					#$query =~ s/[^!-~\s]//g;
					$dns_count_query++;
					#Search for queries and answers with the same transaction ID
					$dns_packets{"$ip_obj->{src_ip}:$udp_obj->{src_port}_$ip_obj->{dest_ip}:$udp_obj->{dest_port}_0x$transaction_id"}++;
					print "[DEBUG] DNS Query (0x$transaction_id): $ip_obj->{src_ip} -> $ip_obj->{dest_ip}\n" if $debug;
					#print "[DEBUG] DNS Query\t$query\n" if $debug;
				}
				#DNS answers
				if ($udp_obj->{src_port} == 53 and $udp_obj->{data}){
					my $dns_raw_data = NetPacket::UDP::strip($ip_obj->{data});
					my $transaction_id = unpack('H*', substr($dns_raw_data,0,2));
					#Better not to print answers since due to the raw data extracted from the packet, there are non-ASCII chars
					#That doesn't allow a better handling of the string and make it look formatted better.
					#my $answer = unpack('A*', substr($dns_raw_data,12)); #Extracts queries from DNS data
					#$answer =~ s/[^!-~\s]//g;
					$dns_count_answer++;
					#Search for queries and answers with the same transaction ID
					$dns_packets{"$ip_obj->{dest_ip}:$udp_obj->{dest_port}_$ip_obj->{src_ip}:$udp_obj->{src_port}_0x$transaction_id"}++;
					print "[DEBUG] DNS Answer (0x$transaction_id): $ip_obj->{src_ip} -> $ip_obj->{dest_ip}\n" if $debug;
					#print "[DEBUG] DNS Answer\t$query\n" if $debug;
				}
			}
		}#End of DNS analysis
	}
	print_tcp_results($tcp_attempts,\%tcp_open,\@tcp_total,\%tcp_closed,\%tcp_filtered);
	print_icmp_results(\%icmp_source,\%icmp_destination,\@icmp_total);
	print_udp_results(\%udp_closed);

	print_ftp_results(\@ftp_packets,$ftp_count_request,$ftp_count_response) if $ftp_info;
	print_http_results(\@http_packets,$http_count_request) if $http_info;
	print_dns_results(\%dns_packets,$dns_count_query,$dns_count_answer) if $dns_info;
}

main();
