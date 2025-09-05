import paramiko
import time
import json
import requests
import getpass
import re
import ipaddress

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
            ssh_client.connect(hostname="10.8.0.22", username="admin", port=3366, password="admin", timeout=30, banner_timeout=60)
        except Exception as e:
            print("No Robustel router found. Please check the connection.")
            print("Enter a key to exit...")
            input()
            return  
        shell = ssh_client.invoke_shell()
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
    except Exception as e:     
        print("exception", e)
    finally:
        # Close the SSH connection
        ssh_client.close()
set_openvpn_client()