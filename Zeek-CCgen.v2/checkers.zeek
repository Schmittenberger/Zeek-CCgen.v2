#
# Covert Channel Checker Functions
#

module CCgenCheckers;

#store connection unqiue ids with their last IP ids
type packetRecord: record {
    #save IP id of a packet
    id: int;
    #save timestamp of last packet to compare how long ago a packet was sent
    timestamp: time;
    #save all seen ids in a set (basic collection of value without mapping to another value)
    #https://docs.zeek.org/en/master/script-reference/types.html#set
    idSet: set[int];
};
# a table of strings which returns a table of ip addresses which yield a packet record
# the table stores connection ids, in that table addresses are stored (sender or receiver) and then to that address a packet record is saved
# used to find out if a sender is using a covert channel with IP ids - that needs to be seperated by connection and address
global connection_table_IP_ids: table[string] of table[addr] of packetRecord;

#a table of connection ids, that maps to a table of covert channel strings that yields an integer
# use to count how many times a covert channel has been found for a given connection
# e.g. CM7Jio2CXB3sYGLrJ1 -> ["TTL": 3]
global connection_ids_to_covert_channel: table[string] of table[string] of int;

#function to store the occurences of covert channels for a given connection id
# returns true once if the exact covert_channel_threshold is reached
# used to stop spamming the notice log
function cc_threshold(uid: string, covert_channel: string): bool{
    #if the connection id has been seen before
    if (uid in connection_ids_to_covert_channel){
        if(covert_channel in connection_ids_to_covert_channel[uid]){
            connection_ids_to_covert_channel[uid][covert_channel] += 1;
            #if the covert channel has been discovered more than the times allowed in the conf.zeek
            # then raise notice aka return T (true) to raise a notice in the calling function
            if(connection_ids_to_covert_channel[uid][covert_channel] == CCgenDetector::covert_channel_threshold){
                return T;
            }
        } else {
            #connection has been saved to table before, but not the covert channel
            connection_ids_to_covert_channel[uid][covert_channel] = 1;
        }
    } else {
        #the connection is being added for the first time,
        # set the amount of times the covert channel has been detected to 1
        local tmp: table[string] of int = {[covert_channel] = 1};
        connection_ids_to_covert_channel[uid] = tmp;        
    }
    return F;
}

export {
    #check packet for a ttl that deviates from the ttl defined in conf.zeek
    function check_ttl(c: connection, ipv4_header: ip4_hdr){
            if (ipv4_header$ttl !in CCgenDetector::allowed_ttls){
                if (cc_threshold(c$uid, "TTL")){
                    #print fmt("Found deviating TTL: %d ", ipv4_header$ttl);
                    NOTICE([$note=CCgenDetector::Potential_TTL_Covert_Channel,
                            $msg="[Zeek-CCgen.v2] Potential Covert Channel identified using TTL !",
                            $sub=fmt("Found TTL of %s (not allowed)", ipv4_header$ttl),
                            $src=ipv4_header$src,
                            $conn=c,
                            $n=8]);
                }
            }
    }

    # check the packet for a reserved bit flag - but this is not available in native zeek :(
    function check_flags(c: connection, ipv4_header: ip4_hdr){
		if (ipv4_header$RF == T){
			#print fmt("Reserved bit flag is set! ");
			#Raise notice!
            if (cc_threshold(c$uid, "flags")){
                NOTICE([$note=CCgenDetector::Potential_IP_Flags_Covert_Channel,
                    $msg="[Zeek-CCgen.v2] Potential Covert Channel identified using the reserved bit flag !",
                    $sub=fmt("Found reserved bit in use %s", ipv4_header),
                    $src=ipv4_header$src,
                    $conn=c,
                    $n=8]);
            }
		}     
    }

    # -- Disclaimer --
    # This check will produce false positives in a "normal" data flow!
    # in a data flow modified by CCgen ipid_v2s however it will achieve 100% true positives
    # -- Disclaimer --
    function check_id(c: connection, ipv4_header: ip4_hdr){
        #in the baseline ICS network analyzed in my work the IP ID increments by one for each packet on the analyzed device
        # with CCgen.v2 ipid_v2s the secret message is embedded one to one (up to 8 bits per packet) in the ID field. 
        
        #get globally unique connection identifier from connection object 
        # compare IP id field to previous identical connection flow
        local connection_u_id = c$uid;
        if (connection_u_id in connection_table_IP_ids){
            if (ipv4_header$src in connection_table_IP_ids[connection_u_id]){
                local packet_record_to_address = connection_table_IP_ids[connection_u_id][ipv4_header$src];
                local last_id = packet_record_to_address$id;
                local last_time = packet_record_to_address$timestamp;
                local idSet = packet_record_to_address$idSet;
                #print fmt("checking connection uid: %s | addr: %s, dst: %s, ip id: %d", connection_u_id, ipv4_header$src, ipv4_header$dst, last_id);

                #boolean to check if a covert channel is suspected/found
                local cc_found = F;

                #check if the id is modulo 256 (because ccgen ipid_v2s multiplies its values by 256) 
                # and if Dont Fragment Flag is unset (because ccgen ipid_v2s unsets the DF flag)
                if ((ipv4_header$id % 256 == 0) && !(ipv4_header$DF as bool)){
                    #if((ipv4_header$id - last_id) > 1 && |network_time() - last_time| < 1) { # commented out because not all devices increment their IDs as baseline behaviour
                    cc_found = T;
                    #}
                }
                #if we find a duplicate id in a connection flow, then it is safe to say that suspicous IDs are used
                if(ipv4_header$id in idSet && !(ipv4_header$DF as bool)){
                    cc_found = T;
                }
                
                if (cc_found){
                    if (cc_threshold(c$uid, "ID")){
                    #print fmt(" [IP ID Field] id channel found in connection id: %s | addr: %s, dst: %s, ip id: %d", connection_u_id, ipv4_header$src, ipv4_header$dst, last_id);
                          NOTICE([$note=CCgenDetector::Potential_IP_Identifcation_Covert_Channel,
                            $msg="[Zeek-CCgen.v2] Potential Covert Channel identified using IP ID Field !",
                                $sub=fmt("Found duplicate or modulo 256 IDs  | previous id: %s <-> current id: %d", last_id, ipv4_header$id),
                                $src=ipv4_header$src,
                                $conn=c,
                                $n=8]);
                    }
                }
                #add current ip id to set, to check later if duplicate ids are used
                add idSet[ipv4_header$id];
                #set current id as last id to check later if ids incrementing
                packet_record_to_address$id = ipv4_header$id;
                #save timestamp of current packet to later compute how long ago the last packet for this connection was
                packet_record_to_address$timestamp = network_time();
            } else{
            #create new packet record entry in connection table with existing address
                local newSet_addr: set[int] = {ipv4_header$id};
                local packet_record_tmp_1 = packetRecord($id = ipv4_header$id, $timestamp = network_time(), $idSet = newSet_addr);
                connection_table_IP_ids[connection_u_id][ipv4_header$src] = packet_record_tmp_1;
            }
        } else {
        # create new address entry in connection table
            #print fmt("connection new, adding to connection_table_IP_ids: %s", connection_u_id);
            local newSet: set[int] = {ipv4_header$id};
            local packet_record_tmp = packetRecord($id = ipv4_header$id, $timestamp = network_time(), $idSet = newSet);
            local table_tmp: table[addr] of packetRecord = {[ipv4_header$src] = packet_record_tmp,};
            connection_table_IP_ids[connection_u_id]= table_tmp;
        }
    }

    function check_tos(c: connection, ipv4_header: ip4_hdr){
        if (ipv4_header$tos > 0){
            if (cc_threshold(c$uid, "TOS")){
                #print fmt(" [TOS] tos channel found in connection id: %s | addr: %s, dst: %s, tos: %d", connection_u_id, ipv4_header$src, ipv4_header$dst, ipv4_header$tos);
                NOTICE([$note=CCgenDetector::Potential_IP_TOS_Covert_Channel,
                        $msg="[Zeek-CCgen.v2] Potential Covert Channel identified using TOS/DSCP field !",
                        $sub=fmt("Found non zero TOS/DSCP: %s", ipv4_header$tos),
                        $src=ipv4_header$src,
                        $conn=c,
                        $n=8]);
            }
        }
            
    }

    function check_urgent_pointer(c: connection, flags: string, urgent: int){
        local urg_flag = F;
        #check flags for urgent flag
        for (i in flags){
            if (i == "U"){
                #print fmt("Urgent Flag is set!!");
                urg_flag = T;
                }
        }

        #The TCP RFC defines that a Urgent Flag indicates that the content of the Urgent Pointer is relevant
        # if the urgent pointer has non null content with an unset URG flag, then it is not following expected behavior
        # --> most probable a suspicous communication which should be alerted of
        if (urgent > 0 && !urg_flag){
            if (cc_threshold(c$uid, "URG")){
                #print fmt("[Zeek-CCgen.v2] Potential Covert Channel identified using Urgent Pointer %s %d",urg_flag, urgent);
                NOTICE([$note=CCgenDetector::Potential_IP_Urgent_Pointer_Covert_Channel,
                        $msg="[Zeek-CCgen.v2] Potential Covert Channel identified using Urgent Pointer !",
                        $sub=fmt("Found Urgent_Pointer channel"),
                        $conn=c,
                        $n=8]);
            }
        }
            
    }

}
