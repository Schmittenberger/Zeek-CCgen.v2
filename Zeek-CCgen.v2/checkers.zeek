#
# Covert Channel Checker Functions
#
@load ./conf

module CCgenCheckers;

#store connection unqiue ids with their last IP ids
global connection_table_IP_ids: table[string] of int;

export {
    #check packet for a ttl that deviates from the ttl defined in conf.zeek
    function check_ttl(c: connection, ipv4_header: ip4_hdr){
            if (ipv4_header$ttl !in CCgenDetector::allowed_ttls){
                print fmt("Found deviating TTL: %d ", ipv4_header$ttl);

                NOTICE([$note=CCgenDetector::Potential_TTL_Covert_Channel,
                        $msg="[Zeek-CCgen.v2] Potential Covert Channel identified using TTL !",
                        $sub=fmt("Found TTL of %s (not allowed)", ipv4_header$ttl),
                        $src=ipv4_header$src,
                        $conn=c,
                        $n=8]);
            }
    }

    # check the packet for a reserved bit flag - but this is not avbailable in native zeek :(
    function check_flags(c: connection, ipv4_header: ip4_hdr){
        
		# if (ipv4_header$RF == 1){
			# print fmt("Reserved bit flag is set! ");
			# TODO: Raise notice!
		# }

                NOTICE([$note=CCgenDetector::Potential_IP_Flags_Covert_Channel,
                      $msg="[Zeek-CCgen.v2] Potential Covert Channel identified using the reserved bit flag !",
                        $sub=fmt("Found reserved bit in use %s", ipv4_header),
                        $src=ipv4_header$src,
                        $conn=c,
                        $n=8]);
            
    }

    function check_id(c: connection, ipv4_header: ip4_hdr){
        #in the baseline ICS network analyzed in my work the IP ID increments by one for each packet
        # with CCgen.v2 ipid_v2s the secret message is embedded one to one (up to 8 bits per packet) in the ID field. 
        
        #get globally unique connection identifier from connection object 
        # compare IP id field to previous identical connection flow
        local connection_u_id = c$uid;
        
        
        if (connection_u_id in connection_table_IP_ids){
            local last_id = connection_table_IP_ids[connection_u_id];
            print fmt("connection uid exists: %s | ip id: %d", connection_u_id, last_id);
            local cc_found = F;
            if (ipv4_header$id == last_id){
                cc_found = T;
            }
            if ((ipv4_header$id - last_id) > 1){
                cc_found = T;
            }
            
            if (cc_found){
                print fmt("Found IDs that do not increment | old: %s ; new: %d", last_id, ipv4_header$id);


                    print fmt("     Source IP: %s", ipv4_header$src);
                    print fmt("     Destination IP: %s", ipv4_header$dst);
                    print fmt("     ID: %d", ipv4_header$id);

                    NOTICE([$note=CCgenDetector::Potential_IP_Identifcation_Covert_Channel,
                        $msg="[Zeek-CCgen.v2] Potential Covert Channel identified using IP ID Field !",
                            $sub=fmt("Found IDs that do not increment | old: %s ; new: %d", last_id, ipv4_header$id),
                            $src=ipv4_header$src,
                            $conn=c,
                            $n=8]);
            }
            connection_table_IP_ids[connection_u_id] = ipv4_header$id;
        } else {
            print fmt("connection new, adding to connection_table_IP_ids: %s", connection_u_id);
            connection_table_IP_ids[connection_u_id] = ipv4_header$id;
        }
        print fmt("|-----|");
        for ( i,j in connection_table_IP_ids ) {
            print fmt("%s = %d",i,j);
        }
        print fmt("|-----|");


    }

    function check_tos(c: connection, ipv4_header: ip4_hdr){
        
        if (ipv4_header$tos > 0){
            print fmt("TOS of > 0 found: %d", ipv4_header$tos);
            NOTICE([$note=CCgenDetector::Potential_IP_TOS_Covert_Channel,
                    $msg="[Zeek-CCgen.v2] Potential Covert Channel identified using TOS/DSCP field !",
                    $sub=fmt("Found non zero TOS/DSCP: %s", ipv4_header$tos),
                    $src=ipv4_header$src,
                    $conn=c,
                    $n=8]);
        }
            
    }

    # TODO
    function check_urgent_pointer(c: connection, tcp_header: tcp_hdr){
        


                NOTICE([$note=CCgenDetector::Potential_IP_Urgent_Pointer_Covert_Channel,
                      $msg="[Zeek-CCgen.v2] Potential Covert Channel identified using Urgent Pointer !",
                        $sub=fmt("Found Urgent_Pointer channel"),
                        $conn=c,
                        $n=8]);
            
    }

}
