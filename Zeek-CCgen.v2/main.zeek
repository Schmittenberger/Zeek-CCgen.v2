##! Test script to analyse TCP packets
##!
##! Results are logged in <not yet>
##!
##! Author:  Lukas Schmidt
##! Contact: schmidtdev@gmx.com
##!
##! 

@load ./conf
#@load base/protocols/ip

# event new_packet(c: connection, p: pkt_hdr) {
#     local p$ip = p$ip;
#     print fmt("IP Packet:");
#     print fmt("  Source IP: %s", p$ip$ip_src);
#     print fmt("  Destination IP: %s", p$ip$ip_dst);
#     print fmt("  Version: %#x", p$ip$version);
#     print fmt("  Header Length: %d", p$ip$ihl);
#     print fmt("  TOS: %#x", p$ip$tos);
#     print fmt("  Length: %d", p$ip$tot_len);
#     print fmt("  ID: %d", p$ip$id);
#     print fmt("  Flags: %#x", p$ip$flags);
#     print fmt("  Fragment Offset: %d", p$ip$frag_off);
#     print fmt("  TTL: %d", p$ip$ttl);
#     print fmt("  Protocol: %d", p$ip$proto);
#     print fmt("  Checksum: %#x", p$ip$csum);
# }

event new_packet(c: connection, p: pkt_hdr){
	# if(p$ip is ip4_hdr){
		# access a field value, e.g. get ip layer from packet: p$ip
		# check if a field exists: p $ ip
	if (p ?$ ip){
		print fmt("has ip packet!");
	}
	if (CCgenDetector::max_prints >0) {
		print fmt("IPv4: %s", p$ip);
		print fmt("New Packet: %s",p);

    # IPv4 = ip | IPv6 = ip6
	if(p ?$ ip6){
		print fmt("zeek rocket");
		print fmt("ip6 test: %s",p$ip6);
	}
	
    print fmt("  Source IP: %s", p$ip$src);
    print fmt("  Destination IP: %s", p$ip$dst);
    print fmt("  Header Length in bytes: %d", p$ip$hl);
    print fmt("  TOS: %d", p$ip$tos);
    print fmt("  Length: %d", p$ip$len);
    print fmt("  ID: %d", p$ip$id);
    print fmt("  Flags: MF %d, DF %d", p$ip$MF, p$ip$DF);
    # print fmt("  Fragment Offset: %d", p$ip$frag_off);
    print fmt("  TTL: %d", p$ip$ttl);
    print fmt("  offset: %d", p$ip$offset);
    #print fmt("  Protocol: %#x", p$ip$);
    print fmt("  Checksum: %d", p$ip$sum);
	--CCgenDetector::max_prints;

	}
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string){
	if (CCgenDetector::max_prints >0) {
		print fmt("Max prints: %s", CCgenDetector::max_prints);
		print fmt("Destination Port #: %s", c$id$resp_p);
		print fmt("connection #: %s", c$id);
		print fmt("connection #: %s", c);
		--CCgenDetector::max_prints;
	}
	
	# local unit_id = headers$uid;
	# if (unit_id !in CCgenDetector::allowed_unit_ids)
	# 	{
	# 		local message = "[CC_UnitID] Potential Covert Channel identified using TTL !";
	# 		local sub_message = fmt("Found TTL %s. (not allowed)", unit_id);

	# 		NOTICE([$note=CCgenDetector::Potential_TTL_Covert_Channel,
	# 				$msg=message,
	#         		$sub=sub_message,
	#         		$conn=c,
	#         		$n=8]);
	# 	}
}
