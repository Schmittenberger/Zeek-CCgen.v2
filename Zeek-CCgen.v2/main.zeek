##! Script to analyse IP and TCP packets for covert channel created with CCgen.v2
##!
##! Results are logged in notice.log
##!
##! Author:  Lukas Schmidt
##!
##! 

@load ./conf
@load ./checkers
global max_prints_const = CCgenDetector::max_prints;


#check each new packet | the docs say this event is resource intensive
event new_packet(c: connection, p: pkt_hdr){
	#ignore ICMP packets - they create false positives for the TOS/DSCP covert channel checker
	# and CCgen does not modify ICMP packets in our lab setup! Of course verify this for your use case
	if (p ?$ icmp){
		return;
	}

	# access a field value, e.g. get ip layer from packet: p$ip
	# check if a ipv4 field exists in the packet header: p ?$ ip
	if (p ?$ ip){
		local ipv4_header = p$ip;
		# print fmt("  Source IP: %s", ipv4_header$src);
		# print fmt("  Destination IP: %s", ipv4_header$dst);
		# print fmt("  Header Length in bytes: %d", ipv4_header$hl);
		# print fmt("  TOS: %d", ipv4_header$tos);
		# print fmt("  Length: %d", ipv4_header$len);
		# print fmt("  ID: %d", ipv4_header$id);
		# print fmt("  Flags: MF %d, DF %d", ipv4_header$MF, ipv4_header$DF);
		# print fmt("  Fragment Offset: %d", ipv4_header$frag_off);
		# print fmt("  TTL: %d", ipv4_header$ttl);
		# print fmt("  offset: %d", ipv4_header$offset);
		# print fmt("  Checksum: %d", ipv4_header$sum);

		#Check TTL for a covert channel
		if (CCgenDetector::check_for_ttl_cc){
			CCgenCheckers::check_ttl(c,ipv4_header);
		}

		# Check for a IP Flags covert channel
		# zeek does not natively offer up the Reserved Bit Flag - use my Zeek-TCP-Urgent-Pointer-fork which includes the Reserved Bit in the IPv4 header
		# check if the reserved bit flag is set, then raise notice that a flag covert channel might be in use
		if (CCgenDetector::check_for_flags_cc){
			CCgenCheckers::check_flags(c,ipv4_header);
		}

		# Check for a IP Identifcation covert channel
		# check for suspicious ids - not incrementing - or randomly changing
		if (CCgenDetector::check_for_identifcation_cc){
			CCgenCheckers::check_id(c,ipv4_header);
		}

		# Check for a IP Type of Service / DSCP covert channel
		# check for non zero TOS
		if (CCgenDetector::check_for_tos_cc){
			CCgenCheckers::check_tos(c,ipv4_header);
		}
	}
}

#check tcp packet - fired for each packet which contains a tcp part
# Warning: the native tcp_packet event does not return the urgent pointer!
# USE MY Zeek-TCP-Urgent-Pointer-fork to get the urgent pointer from this event
event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string, urgent: int){
	CCgenDetector::packet_counter += 1;
	if (CCgenDetector::max_prints >0) {
		print fmt("Debug prints: %d of %d", CCgenDetector::max_prints, max_prints_const);
		#print fmt("  connection #: %s", c);
		print fmt("  seq #: %s", seq);
		print fmt("  urgent #: %d", urgent);
		
		if (CCgenDetector::max_prints == 1){
			print fmt("[Debug:] Packet debug print limit (max_prints in conf.zeek) reached.");
			print fmt("[Debug:] No more packet info will be printed from now on.");
		}
		--CCgenDetector::max_prints;
	}

	# Check for a TCP Urgent Pointer covert channel
	# USE MY Zeek-TCP-Urgent-Pointer-fork to get the urgent pointer from this event
	if (CCgenDetector::check_for_urgent_pointer_cc){
		CCgenCheckers::check_urgent_pointer(c,flags, urgent);
	}
}

event Pcap::file_done(path: string){
	print fmt("Finished processing for %s", path);
		CCgenCheckers::attribute_channel();

}

