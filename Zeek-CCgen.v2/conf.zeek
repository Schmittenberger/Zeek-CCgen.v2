#
# CCgenDetector - Config
#

module CCgenDetector;

export {
	# Notice enum types
	redef enum Notice::Type += { Potential_TTL_Covert_Channel };
	redef enum Notice::Type += { Potential_IP_Flags_Covert_Channel };
	redef enum Notice::Type += { Potential_IP_Identifcation_Covert_Channel };
	redef enum Notice::Type += { Potential_IP_TOS_Covert_Channel };
	redef enum Notice::Type += { Potential_IP_Urgent_Pointer_Covert_Channel };

	# CONFIG

	#enable or disable certain covert channel checks
	#T = True | F = False
	global check_for_ttl_cc = T;
	# use my zeek fork (Zeek-TCP-Urgent-Pointer-fork) which provides the Reserved Bit flag 
	global check_for_flags_cc = T; # zeek does not natively offer up the Reserved Bit Flag
	global check_for_identifcation_cc = T;
	global check_for_tos_cc = T;
	# use my zeek fork (Zeek-TCP-Urgent-Pointer-fork) which provides the Urgent Pointer
	global check_for_urgent_pointer_cc = T;

	# how many times a suspicious channel has to be seen to flag the whole connection as suspicious
	# e.g. if a TTL covert channel is found 5 times for the same connection, then log this to Notice.log
	global covert_channel_threshold = 5;


	# define here which TTLs are allowed/used in your environment
	# all other TTLs will be flagged as suspicious
	global allowed_ttls = [40, 60, 64];

	# to prevent console spam configure max debug prints
	global max_prints = 5;
}
