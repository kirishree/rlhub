import paramiko
import time
import json
import requests
import getpass
import re
import ipaddress
hub_ip = "185.69.209.245"
router_ip = "192.168.88.1"
username = "admin"
password = ""
urllogin = "https://reachlink.cloudetel.com/beapi/auth"
url = "https://reachlink.cloudetel.com/beapi/get_microtekspoke_config"
def send_command(shell, command, wait_time=2):
    shell.send(command + '\n')
    time.sleep(wait_time)  # Wait for the command to be processed  
    return 

def send_command_wo(shell, command, delay=1):
    shell.send(command + '\n')
    time.sleep(delay)
    output = shell.recv(65535).decode('utf-8')
    return output

def set_openvpn_client(spokeinfo):
    # Define the router details 
    # Create an SSH client instance
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect to the router
        ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=30, banner_timeout=60)
        # Execute the ping command
        clientname = "reachlink"
        certname = clientname + "_1"
        stdin, stdout, stderr = ssh_client.exec_command(f'interface ovpn-client add name=reachlink max-mtu=1500 connect-to={hub_ip} port=1194 mode=ip user={clientname} profile=default-encryption certificate={certname} verify-server-certificate=yes auth=sha1 cipher=aes256 use-peer-dns=yes  add-default-route=no')
        stdin, stdout, stderr = ssh_client.exec_command(f'snmp set enabled=yes')
        stdin, stdout, stderr = ssh_client.exec_command(f'ip firewall filter add chain=input protocol=udp src-address=10.8.0.0/24 dst-port=161 action=accept place-before=0 comment=enable-snmpaccess')
        stdin, stdout, stderr = ssh_client.exec_command(f'user add name={spokeinfo["router_username"]} password={spokeinfo["router_password"]} group=full')
        stdin, stdout, stderr = ssh_client.exec_command(f'snmp community add addresses=0.0.0.0/0 name={spokeinfo["snmpcommunitystring"]} read-access=yes comment=reachlinkserver')
        stdin, stdout, stderr = ssh_client.exec_command(f'ip firewall filter add chain=input action=accept protocol=tcp src-address=10.8.0.0/24 dst-port=22 comment=enable-ssh place-before=0')
        stdin, stdout, stderr = ssh_client.exec_command(f'ip firewall filter add chain=input action=accept protocol=tcp src-address=10.8.0.0/24 dst-port=8291 place-before=0 comment=enable-winboxaccess')
        stdin, stdout, stderr = ssh_client.exec_command(f'ip route add dst-address=0.0.0.0/0 gateway=10.8.0.1 routing-mark=reachlink')        
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
                "branch_loc":branch_loc
                } 
    json_data = json.dumps(userinfo)
    try:
        response = requests.post(url, data=json_data, headers=headers)  # Timeout set to 5 seconds
        response.raise_for_status()
        if response.status_code == 200:           
            json_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
            spokeinfo = json.loads(json_response)
            if  "This Microtek Spoke is already Registered" not in spokeinfo["message"]:
                print(spokeinfo["message"])  
                print("Enter a key to exit...")
                input()
                return            
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
    print("Start to configure")
    set_openvpn_client(spokeinfo)

if __name__ == "__main__":
    main()