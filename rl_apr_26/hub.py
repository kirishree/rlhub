"""
This script should be run in HUB for creating GRE Tunnel in the name of Reach_link1.
Tunnel in HUB as point to multipoint.
"""
import os
os.system("sudo ip tunnel add Reach_link1 mode gre local 185.69.209.245 remote any ttl 255")
os.system("sudo ip addr add 10.200.203.1/24 dev Reach_link1")
os.system("sudo ip link set up dev Reach_link1")
os.system("sudo ip link set mtu 1476 dev Reach_link1")