import paramiko
import time
import json
import requests
import getpass
import re
import ipaddress
hub_ip = "185.69.209.251"

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
    router_ip = "172.23.3.21"
    username = "admin"
    password = "admin"

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
                            "set firewall white_list 1 src_addr 172.23.3.0/24",
                            "add firewall white_list 2",
                            "set firewall white_list 2 desc reachlinkserver",
                            "set firewall white_list 2 src_addr 185.69.209.251/32",
                            "add firewall white_list 3",
                            "set firewall white_list 3 desc reachlinknetwork",
                            "set firewall white_list 3 src_addr 10.8.0.0/24",
                            "set firewall remote_telnet_access false",
                            "set firewall remote_https_access false",
                            "set firewall remote_ssh_access false",
                            "set firewall local_ssh_access true",
                            "set firewall local_telnet_access true"                                                        
                            ]
        for command in config_commands:
            output = send_command_wo(shell, command)
            if "OK" in output:
                print(command, "success")
            else:
                print(command, "failed")
                ssh_client.close()                
                print("Error while configuring pl try again.")
                print("Enter a key to exit...")
                input()
                return
        output = send_command_wo(shell, "config save_and_apply")
    except Exception as e:
        print(e)
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
    password = getpass.getpass() 
    urllogin = "https://reachlink.cloudetel.com/auth"
    headers = {"Content-Type": "application/json"}
    authinfo = json.dumps({"username": username,"password": password})
    try:
        authresponse = requests.post(urllogin, data= authinfo, headers= headers)
        authresponse.raise_for_status()
        if authresponse.status_code == 200:           
            json_authresponse = authresponse.text.replace("'", "\"")  # Replace single quotes with double quotes
            json_authresponse = json.loads(json_authresponse)
            if "access" not in json_authresponse:
                print(json_authresponse["message"])  
                print("Enter a key to exit...")
                input()
                return
            else:
                print(json_authresponse)
                access_token = json_authresponse["access"]
                set_openvpn_client() 
                return
        else:
            print("Error while authenticating data")
            print("Enter a key to exit...")
            input()
            return
    except Exception as e:
        print("Error while getting configuration: {e}")
        print("Enter a key to exit...")
        input()
    return

if __name__ == "__main__":
    main()