import ipaddress
addr = "192.168.23.149/30"
corrected_subnet = ipaddress.ip_network(addr, strict=False)
print(corrected_subnet)