##! Test script to analyse TCP packets
##!
##! Results are logged in notice.log
##!
##! Author:  Lukas Schmidt
##! Contact: schmidtdev@gmx.com
##!
##! 

@load ./conf
@load ./checkers
#@load base/protocols/ip

event new_packet(c: connection, p: pkt_hdr){
	# access a field value, e.g. get ip layer from packet: p$ip
	# check if a ipv4 field exists in the packet header: p ?$ ip
	if (p ?$ ip){
		local ipv4_header = p$ip;
		# print fmt("has ip packet!");
		# print fmt("  Source IP: %s", ipv4_header$src);
		# print fmt("  Destination IP: %s", ipv4_header$dst);
		# print fmt("  Header Length in bytes: %d", ipv4_header$hl);
		# print fmt("  TOS: %d", ipv4_header$tos);
		# print fmt("  Length: %d", ipv4_header$len);
		# print fmt("  ID: %d", ipv4_header$id);
		# print fmt("  Flags: MF %d, DF %d", ipv4_header$MF, ipv4_header$DF);
		# # print fmt("  Fragment Offset: %d", ipv4_header$frag_off);
		# print fmt("  TTL: %d", ipv4_header$ttl);
		# print fmt("  offset: %d", ipv4_header$offset);
		# print fmt("  Checksum: %d", ipv4_header$sum);

	#Check TTL for a covert channel
	if (CCgenDetector::check_for_ttl_cc){
		CCgenCheckers::check_ttl(c,ipv4_header);
	}

	# Check for a IP Flags covert channel
	# # zeek does not natively offer up the Reserved Bit Flag - TODO
	# check if the reserved bit flag is set, then raise notice that a flag covert channel might be in use
	if (CCgenDetector::check_for_flags_cc){
		#CCgenCheckers::check_flags(c,ipv4_header)
	}

	# Check for a IP Identifcation covert channel
	# check for sus ids - not incrementing - or randomly changing
	if (CCgenDetector::check_for_identifcation_cc){
		CCgenCheckers::check_id(c,ipv4_header);
	}

	# Check for a IP Type of Service / DSCP covert channel
	# check for non zero TOS
	if (CCgenDetector::check_for_tos_cc){
		CCgenCheckers::check_tos(c,ipv4_header);
	}





	} else{
		print fmt("Packet does not have an IPv4 Header");
	}

	if (CCgenDetector::max_prints >0) {
		print fmt("IPv4: %s", p$ip);
		print fmt("New Packet: %s",p);

		# IPv4 = ip | IPv6 = ip6
		# if(p ?$ ip6){
		# 	print fmt("ip6 test: %s",p$ip6);
		# }
		--CCgenDetector::max_prints;
	}
}

#check tcp packet - fired for each packet which contains a tcp part
event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string){
	if (CCgenDetector::max_prints >0) {
		print fmt("Max prints: %s", CCgenDetector::max_prints);
		print fmt("Destination Port #: %s", c$id$resp_p);
		print fmt("connection #: %s", c$uid);
		print fmt("connection #: %s", c);
		--CCgenDetector::max_prints;
	}

	
		# Check for a TCP Urgent Pointer covert channel
		# 
		if (CCgenDetector::check_for_urgent_pointer_cc){
			#CCgenCheckers::check_urgent_pointer(c,p$);
		}
	

}

