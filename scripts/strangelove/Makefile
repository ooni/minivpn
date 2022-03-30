# 
# strangelove: using DPI for the common good.
#
# This file, for now, is just a bunch of snippets using the super-awesome netfilter module for nDPI.
# thanks to vmon for some documentation of what's possible: 
# https://internetfreedomfestival.org/wiki/index.php/Playing_cat_and_mouse_with_Deep_Packet_Inspection
#
# and to vel21ripn for maintaining an up-to-date fork: https://github.com/vel21ripn/nDPI 
#
# In the future this could be integrated into filternet/jafar.
# Before doing that, working on a dkms version of xt_ndpi is probably a good idea.
#
VPNBLOCK=-m ndpi --proto openvpn
LIMIT=-m limit --limit
5_SEC=5/sec
10_SEC=10/sec
PACKETLIMIT=-m connbytes --connbytes 20:20 --connbytes-dir both --connbytes-mode packets

throttle-5:
	# throttles at 5 packets/s
	iptables -I OUTPUT ${VPNBLOCK} -j DROP
	iptables -I OUTPUT ${VPNBLOCK} ${LIMIT} ${5_SEC} -m state --state ESTABLISHED -j ACCEPT

throttle-10:
	# throttles at 10 packets/s
	iptables -I OUTPUT ${VPNBLOCK} -j DROP
	iptables -I OUTPUT ${VPNBLOCK} ${LIMIT} ${10_SEC} -m state --state ESTABLISHED -j ACCEPT

packetlimit:
	# not sure what this is doing, seems a rate?
	iptables -A OUTPUT ${VPNBLOCK} ${PACKETLIMIT} -j DROP

quota:
	# quota: ~2.7 MB
	iptables -A OUTPUT ${VPNBLOCK} -m quota --quota 200000 -j ACCEPT  -c 0 0
	iptables -A OUTPUT ${VPNBLOCK} -m quota --quota 200000 -j LOG --log-prefix "quota-over: " --log-level 4
	iptables -A OUTPUT ${VPNBLOCK} -j DROP

stopwatch:
	# drop connection after 10 seconds
	iptables -A OUTPUT ${VPNBLOCK} -m state --state NEW -m recent --set
	iptables -A OUTPUT ${VPNBLOCK} -m state --state ESTABLISHED -m recent --rcheck --seconds 10 -j ACCEPT
	iptables -A OUTPUT ${VPNBLOCK} -m state --state ESTABLISHED -j LOG
	iptables -A OUTPUT ${VPNBLOCK} -m state --state ESTABLISHED -j DROP

clean:
	@echo "[+] Flushing all rules"
	@iptables -F
