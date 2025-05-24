import paramiko
import time
import json
import requests
import getpass
import re
import ipaddress
hub_ip = "185.69.209.245"
hub_ip_whitelist = "185.69.209.245/32"
router_ip = "192.168.0.1"
username = "admin"
password = "admin"
urllogin = "https://reachlink.cloudetel.com/beapi/auth"
url = "https://reachlink.cloudetel.com/beapi/get_robustelspoke_config"
def send_command(shell, command, wait_time=2):
    shell.send(command + '\n')
    time.sleep(wait_time)  # Wait for the command to be processed  
    return 

def send_command_wo(shell, command, delay=1):
    shell.send(command + '\n')
    time.sleep(delay)
    output = shell.recv(65535).decode('utf-8')
    return output

def set_openvpn_client():
    """
    Connects to a Robustel router via SSH and create OpenVPN tunnel in client mode'.
    """
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, password=password, timeout=30, banner_timeout=60)
        except Exception as e:
            print("No Robustel router found. Please check the connection.")
            print("Enter a key to exit...")
            input()
            return  
        shell = ssh_client.invoke_shell()
        # Send the command and get the output
        config_commands = [
                            "add openvpn tunnel 1",
                            "set openvpn tunnel 1 enable true",
                            "set openvpn tunnel 1 desc reachlink",
                            "set openvpn tunnel 1 mode client",
                            "set openvpn tunnel 1 protocol tcp_client",
                            f"set openvpn tunnel 1 peer_addr {hub_ip}",
                            "set openvpn tunnel 1 peer_port 1194",
                            "set openvpn tunnel 1 interface_type tun",
                            "set openvpn tunnel 1 auth_type x509ca",
                            "set openvpn tunnel 1 encryption aes_256",
                            "set openvpn tunnel 1 authentication sha1",
                            "set openvpn tunnel 1 compress_enable false",
                            "add lan multi_ip 1",
                            "set lan multi_ip 1 ip 192.168.2.1",
                            "set lan multi_ip 1 netmask 255.255.255.0",
                            "add firewall white_list 1",
                            "set firewall white_list 1 desc localnetwork",
                            "set firewall white_list 1 src_addr 192.168.0.0/24",
                            "add firewall white_list 2",
                            "set firewall white_list 2 desc reachlinkserver",
                            f"set firewall white_list 2 src_addr {hub_ip_whitelist}",
                            "add firewall white_list 3",
                            "set firewall white_list 3 desc reachlinknetwork",
                            "set firewall white_list 3 src_addr 10.8.0.0/24",
                            "set firewall remote_telnet_access false",
                            "set firewall remote_https_access false",
                            "set firewall remote_ssh_access false",
                            "set firewall local_ssh_access true",
                            "set firewall local_telnet_access true",
                            "add route static_route 1",
                            "set route static_route 1 desc secdnsroute",
                            "set route static_route 1 destination 8.8.4.4",
                            "set route static_route 1 netmask 255.255.255.255",
                            "set route static_route 1 interface wwan", 
                            "add route static_route 2",
                            "set route static_route 2 desc pridnsroute",
                            "set route static_route 2 destination 8.8.8.8",
                            "set route static_route 2 netmask 255.255.255.255",
                            "set route static_route 2 interface wwan",  
                            "set openvpn tunnel 1 mtu 1500"                                                                                        
                            ]
        for command in config_commands:
            output = send_command_wo(shell, command)
            if "OK" not in output: 
                if "add" in command:
                    continue         
                print(command, "failed")
                ssh_client.close()                
                print("Error while configuring pl try again.")
                print("Enter a key to exit...")
                input()
                return
        print("Is this device supports SNMP?")
        output = send_command_wo(shell, "set snmp enable true")
        if "OK" in output:
            print("Yes, it supports SNMP, starts to configure")
            output = send_command_wo(shell, "set snmp version snmpv1v2v3")
            if "OK" in output:
                output = send_command_wo(shell, "set snmp rocommunity reachlink")
                if "OK" in output:
                    output = send_command_wo(shell, "set snmp rwcommunity reachlink")
                    if "OK" in output:
                        print("SNMP Configured successfully") 
        else:
            print("This device doesn't support SNMP")
        output = send_command_wo(shell, "set ssh port 3366")
        if "OK" in output:
            output = send_command_wo(shell, "config save_and_apply")
    except Exception as e:        
        print("Error while configuring pl try again.")
        print("Enter a key to exit...")
        input()
        return
    finally:
        # Close the SSH connection
        ssh_client.close()
    print("Configuration done. Pl upload the configuration files.")
    print("Enter a key to exit...")
    input()
    return

def is_valid_ip(ip):
    """Check if the IP address is valid (IPv4 or IPv6)."""
    try:
        ipaddress.ip_address(ip)  # If this doesn't raise an error, it's a valid IP
        return True
    except ValueError:
        return False
    
def is_valid_email(email):
    """Validate email format."""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None

def main():    
    while True:
        username = input("Enter the Registered username with ReachLink\nUsername (Mail ID): ")
        if is_valid_email(username):
            break  # Exit the loop if email is valid
        else:
            print("❌ Invalid email format. Please enter a valid email.")
    print(f"Enter the password of {username}:")
    while True:
        password = getpass.getpass()
        if not password.strip():
            print("Password cannot be empty. Please try again.")
        else:
            break 
    print(f"Enter the registered device(branch) location:")
    branch_location = input()
    branch_loc = branch_location.lower()    
    headers = {"Content-Type": "application/json"}
    authinfo = json.dumps({"username": username,"password": password})
    try:
        authresponse = requests.post(urllogin, data= authinfo, headers= headers)
        authresponse.raise_for_status()
        if authresponse.status_code == 200:           
            json_authresponse = authresponse.text.replace("'", "\"")  # Replace single quotes with double quotes
            json_authresponse = json.loads(json_authresponse)
            if "access" not in json_authresponse:
                if not (json_authresponse["message"]):                
                    print(json_authresponse["msg_status"])
                print("Enter a key to exit...")
                input()
                return
            else:       
                print("Login Successfull. Getting configuration...")             
                access_token = json_authresponse["access"]                
        else:
            print("Error while authenticating data")
            print("Enter a key to exit...")
            input()
            return
    except Exception as e:
        print(f"Error while getting configuration: {e}")
        print("Enter a key to exit...")
        input()
        return
    # Set the headers to indicate that you are sending JSON data
    headers = {"Content-Type": "application/json",
               "Authorization": f"Bearer {access_token}"}
    userinfo = {"username": username,
                "password": password,
                "branch_loc": branch_loc
                } 
    json_data = json.dumps(userinfo)
    try:
        response = requests.post(url, data=json_data, headers=headers)  # Timeout set to 5 seconds
        response.raise_for_status()
        if response.status_code == 200:           
            json_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
            spokeinfo = json.loads(json_response)
            if  "This Robustel Spoke is already Registered" not in spokeinfo["message"]:
                print(spokeinfo["message"])                
            else:                
                print("Start to configure")                
                set_openvpn_client() 
                return          
        else:
            print("Error while authenticating data")            
    except Exception as e:
        print(f"Error while getting configuration. Pl try again!")
    print("Enter a key to exit...")
    input()
    return   

if __name__ == "__main__":
    main()