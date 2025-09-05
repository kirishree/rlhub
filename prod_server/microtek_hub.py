import paramiko
import os
import ipaddress

def run_cmd(ssh_client, cmd):
    """Helper to run a command and print stdout/stderr for visibility"""
    stdin, stdout, stderr = ssh_client.exec_command(cmd)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if out:
        print(f"[STDOUT] {cmd}\n{out}")
    if err:
        print(f"[STDERR] {cmd}\n{err}")
        raise RuntimeError(f"Command failed: {cmd}\nError: {err}")
    return out, err

def get_ip_addresses(ip_address, netmask):
    # Create an IPv4Network object representing the subnet
    subnet = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
    # Get the subnet ID and broadcast address
    subnet_id = subnet.network_address
    broadcast_ip = subnet.broadcast_address

    # Extract and return the list of host IPs (excluding subnet ID and broadcast IP)
    #host_ips = [str(ip) for ip in subnet.hosts()]
    
    if subnet.prefixlen == 31:
        # For /31, both IPs can act as hosts (point-to-point links)
        first_host = subnet.network_address
        last_host = subnet.broadcast_address
    else:
        # For other subnets, calculate first and last host IPs
        first_host = subnet.network_address + 1
        last_host = subnet.broadcast_address - 1

   
    host_ips = [first_host, last_host]    
    return {
        "Subnet_ID": str(subnet_id),
        "Broadcast_IP": str(broadcast_ip),
        "Host_IPs": host_ips
    }

def prefix_len_to_netmask(prefix_len):
    # Validate the prefix length
    #print(prefix_len)
    prefix_len = int(prefix_len)
    if not 0 <= prefix_len <= 32:
        raise ValueError("Prefix length must be between 0 and 32")
    # Calculate the netmask using bitwise operations
    netmask = 0xffffffff ^ (1 << (32 - prefix_len)) - 1
    # Format the netmask into IP address format
    netmask_str = ".".join(str((netmask >> i) & 0xff) for i in [24, 16, 8, 0])
    return netmask_str

def openvpnserverconfig(data):
    router_ip = data["hub_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]
    public_ip = router_ip
    openvpn_network = data["overlay_network_addr"]
    
    openvpn_network_netmask = prefix_len_to_netmask(openvpn_network.split("/")[1])
    openvpn_network_addr = openvpn_network.split("/")[0]  
    ip_addresses = get_ip_addresses(openvpn_network_addr, openvpn_network_netmask) 
    pool_start_addr = ip_addresses["Host_IPs"][0]
    pool_end_addr = ip_addresses["Host_IPs"][1]
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh_client.connect(
            hostname=router_ip,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False
        )

        # Create CA
        ca_cmd = f"""
            /certificate add \
            name=CA \
            country=SA \
            state=Jeddah \
            locality=Jeddah \
            organization=CloudEtel \
            unit=ReachLink \
            common-name={public_ip} \
            subject-alt-name=IP:{public_ip} \
            key-usage=key-cert-sign,crl-sign
        """
        run_cmd(ssh_client, ca_cmd)
        run_cmd(ssh_client, f"/certificate sign CA ")

        # Server cert
        server_cert_cmd = f"""
            /certificate add \
            name=Server \
            country=SA \
            state=Jeddah \
            locality=Jeddah \
            organization=CloudEtel \
            unit=ReachLink \
            common-name={public_ip} \
            subject-alt-name=IP:{public_ip} \
            key-usage=digital-signature,key-encipherment,tls-server
        """
        run_cmd(ssh_client, server_cert_cmd)
        run_cmd(ssh_client, "/certificate sign Server ca=CA")

        # Client cert
        client_cert_cmd = f"""
            /certificate add \
            name=Client \
            country=SA \
            state=Jeddah \
            locality=Jeddah \
            organization=CloudEtel \
            unit=ReachLink \
            common-name={public_ip} \
            key-usage=tls-client
        """
        run_cmd(ssh_client, client_cert_cmd)
        run_cmd(ssh_client, "/certificate sign Client ca=CA")

        # IP pool, profile, secret
        run_cmd(ssh_client, f"/ip pool add name=ovpn-pool ranges={pool_start_addr}-{pool_end_addr}")
        run_cmd(ssh_client, f"/ppp profile add name=ovpn-profile local-address={openvpn_network_addr} remote-address=ovpn-pool")
        run_cmd(ssh_client, "/ppp secret add name=rlhub password=rlpass profile=ovpn-profile service=ovpn")

        # Enable OVPN server
        run_cmd(ssh_client, f"/interface ovpn-server server set enabled=yes certificate=Server auth=sha1 cipher=aes256 default-profile=ovpn-profile require-client-certificate=yes")

        # Export certs
        run_cmd(ssh_client, "/certificate export-certificate CA")
        run_cmd(ssh_client, "/certificate export-certificate Client export-passphrase=rl123456")

        # Download certs via SFTP
        sftp = ssh_client.open_sftp()
        sftp.get("cert_export_CA.crt", "./cert_export_CA.crt")
        sftp.get("cert_export_Client.crt", "./cert_export_Client.crt")
        sftp.get("cert_export_Client.key", "./cert_export_Client.key")
        sftp.close()

        # Build OVPN config with embedded certs
        with open("./cert_export_CA.crt") as f:
            ca_content = f.read()
        with open("./cert_export_Client.crt") as f:
            client_crt_content = f.read()
        with open("./cert_export_Client.key") as f:
            client_key_content = f.read()

        ovpn_template = f"""
client
dev tun
proto tcp-client
remote {public_ip} 1194
auth SHA1
cipher AES-256-CBC
nobind
persist-key
persist-tun
remote-cert-tls server

<ca>
{ca_content}
</ca>

<cert>
{client_crt_content}
</cert>

<key>
{client_key_content}
</key>
"""
        with open("client.ovpn", "w") as f:
            f.write(ovpn_template.strip())

        print("✅ OpenVPN client.ovpn created successfully!")

        #stdin, stdout, stderr = ssh_client.exec_command(f'snmp set enabled=yes')
        #stdin, stdout, stderr = ssh_client.exec_command(f'ip firewall filter add chain=input protocol=udp src-address=10.8.0.0/24 dst-port=161 action=accept place-before=0 comment=enable-snmpaccess')
        stdin, stdout, stderr = ssh_client.exec_command(f'user add name={data["new_username"]} password={data["new_password"]} group=full')
        #stdin, stdout, stderr = ssh_client.exec_command(f'snmp community add addresses=0.0.0.0/0 name={data["snmpcommunitystring"]} read-access=yes comment=reachlinkserver')
        #stdin, stdout, stderr = ssh_client.exec_command(f'ip firewall filter add chain=input action=accept protocol=tcp src-address=10.8.0.0/24 dst-port=22 comment=enable-ssh place-before=0')
        #stdin, stdout, stderr = ssh_client.exec_command(f'ip firewall filter add chain=input action=accept protocol=tcp src-address=10.8.0.0/24 dst-port=8291 place-before=0 comment=enable-winboxaccess')
        status = True
    except Exception as e:
        print("❌ Error:", e)
        status = False
        
    finally:
        ssh_client.close()
    return status

data = {"tunnel_ip":"10.8.0.6",
        "router_username":"admin",
        "router_password":"",
        "public_ip":"10.8.0.6",
        "overlay_network_addr":"10.10.0.1",
        "pool_start_addr":"10.10.0.10",
        "pool_end_addr":"10.10.0.100"
        }
#openvpnserverconfig(data)