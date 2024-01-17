#
# Tcp Test - Config
#

module CCgenDetector;

export {
	redef enum Notice::Type += { Potential_TTL_Covert_Channel };

	# CONFIG
	# define here which TTLs are allowed/used in your environment
	global allows_ttls = [40, 60];
	global max_prints = 10;
}
