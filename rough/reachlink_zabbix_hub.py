import requests
import json
import pymongo
import time
client = pymongo.MongoClient("mongodb://cloudetel:Cloudetel0108@185.69.209.251:27017/")
db = client["reach_link"]
coll_reachlink_zabbix_info = db["reachlink_zabbix_info"]
coll_hub_info = db["hub_info"]
coll_registered_organization = db["registered_organization"]

# Zabbix API URL
zabbix_api_url = 'http://185.69.209.251/zabbix/api_jsonrpc.php'  # Replace with your Zabbix API URL

# Zabbix API credentials
username = 'Admin'
password = 'zabbix'

# Api key
auth_token = "de4bc85eca6a76481473f6e4efa71812ee7995c02ace600a62b750bc04841810"

# Create a session
session = requests.Session()
reachlink_current_info = []

def tunnel_ip_info():
    global reachlink_current_info
    try:
        registered_organization = list(coll_registered_organization.find({}))  # Convert cursor to list
        tunnelIPs = list(coll_hub_info.find({}))  # Convert cursor to list

        # Prepare the output list
        data = []
        for organization in registered_organization:
            for device in organization.get("registered_devices", []):  # Use .get() to avoid KeyError
                # Match tunnel IPs with the current device's UUID
                for spokeip in tunnelIPs:
                    if spokeip.get("uuid") == device.get("uuid"):  # Use .get() for safe access
                        # Create a new dictionary to avoid mutability issues
                        matched_spokeip = spokeip.copy()
                        matched_spokeip["hubdevice_name"] = device.get("spokedevice_name")
                        matched_spokeip["company_name"] = organization.get("organization_name")
                        matched_spokeip["username"] = organization.get("regusers", [{}])[0].get("username", "Unknown")
                        # Append the enriched data to the list
                        data.append(matched_spokeip)

                        
    except Exception as e:
        print(f"Error while getting spokes details:{e}")
    reachlink_current_info = data

                    
def get_host_list():
    coll_reachlink_zabbix_info.delete_many({})
    get_host = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "output": ["hostid", "host"],
            "selectInterfaces": ["ip"]
        },
        'auth': auth_token,
        'id': 1,
    }
    try:
        update_response = session.post(zabbix_api_url, json=get_host)
        update_result1 = update_response.json()
        update_result = update_result1.get('result')
        if 'error' in update_result:
            print(f"Failed to get Host list: {update_result['error']['data']}")
            return False
        else:
            for host in update_result:
                coll_reachlink_zabbix_info.insert_one({"Host_name":host['host'], 
                                                        "Host_ip":host['interfaces'][0]['ip'], 
                                                        "Host_id":host['hostid']
                                                        }
                                                       )
            return True
    except Exception as e:
        print(f"Failed to get Host list: {e}")
        return False   
def check_usergroup(host_organization):
    get_user_groupid_payload = {
        "jsonrpc": "2.0",
        "method": "usergroup.get",
        "params": {
        "output": "extend",
        "status": 0
        
    },
        'auth': auth_token,
        'id': 1,
    }

    try:
        update_response = session.post(zabbix_api_url, json=get_user_groupid_payload)
        update_result = update_response.json()
        groupid = "null"
        if 'error' in update_result:
            print(f"Failed to get user group id: {update_result['error']['data']}")
            return False
        else:
            for group in update_result["result"]:
                if group["name"] == host_organization:
                    #print("User group found successfully.")
                    groupid = group["usrgrpid"]
            return groupid
    except Exception as e:
        print(f"Failed to get user group id: {e}")
        return False   


# Create
def create_user_group(groupname):
    create_user_group_payload = {
        "jsonrpc": "2.0",
        "method": "usergroup.create",
        "params": {
        "name": groupname
        },
        'auth': auth_token,
        'id': 1,
    }

    try:
        update_response = session.post(zabbix_api_url, json=create_user_group_payload)
        update_result = update_response.json()
        if 'error' in update_result:
            print(f"Failed to create new user group: {update_result['error']['data']}")
            return False
        else:
            #print("User group created successfully.")
            user_group_id = update_result["result"]["usrgrpids"][0]
            return user_group_id
    except Exception as e:
        print(f"Failed to update host IP address: {e}")
        return False
    
def create_user(roleid, groupid, mailid, username, passwd):
    create_user_payload = {
        "jsonrpc": "2.0",
        "method": "user.create",
        "params": {
        "username": username,
        "passwd": passwd,
        "roleid": roleid,
        "usrgrps": [
            {
                "usrgrpid": groupid
            }
        ],
        "medias": [
            {
                "mediatypeid": "1",
                "sendto": [
                    mailid
                ],
                "active": 0,
                "severity": 63,
                "period": "1-7,00:00-24:00"
            }
        ]
    },
        'auth': auth_token,
        'id': 1,
    }

    try:
        update_response = session.post(zabbix_api_url, json=create_user_payload)
        update_result = update_response.json()
        if 'error' in update_result:
            print(f"Failed to create new user: {update_result['error']['data']}")
            return False
        else:
            #print(f"User {username} created successfully.")
            user_id = update_result["result"]["userids"][0]
            return user_id
    except Exception as e:
        print(f"Failed to create new host: {e}")
        return False
    
def create_user_role(rolename):
    create_user_role_payload = {
        "jsonrpc": "2.0",
        "method": "role.create",
        "params": {
        "name": rolename,
        "type": "1",
        "rules": {
            "ui": [
                {
                    "name": "monitoring.hosts",
                    "status": "0"
                },
                {
                    "name": "monitoring.maps",
                    "status": "0"
                }
            ]
        }
    },
        'auth': auth_token,
        'id': 1,
    }

    try:
        update_response = session.post(zabbix_api_url, json=create_user_role_payload)
        update_result = update_response.json()
        if 'error' in update_result:
            print(f"Failed to create new user role {rolename}: {update_result['error']['data']}")
            return False
        else:
            #print("User role created successfully.")
            user_role_id = update_result["result"]["roleids"][0]
            return user_role_id
    except Exception as e:
        print(f"Failed to create user role: {e}")
        return False

def create_host_group(hostgroupname):
    create_host_group_payload = {
        "jsonrpc": "2.0",
        "method": "hostgroup.create",
        "params": {
            "name": hostgroupname
        },
        'auth': auth_token,
        'id': 1,
    }

    try:
        update_response = session.post(zabbix_api_url, json=create_host_group_payload)
        update_result = update_response.json()
        if 'error' in update_result:
            print(f"Failed to create new host group {hostgroupname}: {update_result['error']['data']}")
            return False
        else:
            #print("Host group created successfully.")
            host_group_id = update_result["result"]["groupids"][0]
            return host_group_id
    except Exception as e:
        print(f"Failed to craete new host group: {e}")
        return False

# Update host interface with the new IP address
def create_hosts(new_host, new_ip, hostgroupid):
    create_host_payload = {
        'jsonrpc': '2.0',
        'method': 'host.create',
        "params": {
            "host": new_host,
            "name": new_host,
            "interfaces": [
                {
                    "type": 2,
                    "main": 1,
                    "useip": 1,
                    "ip": new_ip.split("/")[0],
                    "dns": "",
                    "port": "161",
                    "details": {
                        "version": 2,
                        "community": "reachlink"
                    }
                }
            ],
            "groups": [
                {
                    "groupid": hostgroupid
                }
            ],
            "templates": [
                {
                    "templateid":"10218"
				
                }
            ],
            "inventory_mode": 0
        },
        'auth': auth_token,
        'id': 1,
    }

    try:
        update_response = session.post(zabbix_api_url, json=create_host_payload)
        update_result = update_response.json()
        if 'error' in update_result:
            print(f"Failed to create host: {new_host}: {update_result['error']['data']}")
            return False
        else:
            host_id = update_result["result"]["hostids"][0]
            #print("Host created successfully.")
            filter = {"hub_dialer_ip": new_ip}
            update = {"$set": {"host_id": host_id}}
            coll_hub_info.update_one(filter, update)       
            return host_id
    except Exception as e:
        print(f"Failed to create host: {new_host}: {e}")
        return False

def action_trigger(triggerName, hostid, usergroupid):
    action_trigger_payload = {
    "jsonrpc": "2.0",
    "method": "action.create",
    "params": {
        "name": triggerName,
        "eventsource": 0,
        "esc_period": "30m",
        "filter": {
            "evaltype": 2,
            "conditions": [
                {
                    "conditiontype": 1,
                    "operator": 0,
                    "value": hostid
                },
                {
                    "conditiontype": 3,
                    "operator": 2,
                    "value": "Link down"
                },
                {
                   "conditiontype": 3,
                   "operator": 2,
                   "value": "Zabbix agent is not available"
                }
            ]
        },
        "operations": [
            {
                "operationtype": 0,
                "esc_step_from": 1,
                "esc_step_to": 1,
                "opmessage_grp": [
                    {
                        "usrgrpid": usergroupid
                    }
                ],
                "opmessage": {
                    "default_msg": 1,
                    "mediatypeid": "1"
                }
            }
            
        ],
        "recovery_operations": [
            {
                "operationtype": "11",
                "opmessage": {
                    "default_msg": 1
                }
            }
        ],
        "update_operations": [
            {
                "operationtype": "12",
                "opmessage": {
                    "default_msg": 0,
                    "message": "Custom update operation message body",
                    "subject": "Custom update operation message subject"
                }
            }
        ]
    },
        'auth': auth_token,
        'id': 1,
    }

    try:
        update_response = session.post(zabbix_api_url, json=action_trigger_payload)
        update_result = update_response.json()
        if 'error' in update_result:
            print(f"Failed to create new trigger: {update_result['error']['data']}")
            return False
        else:
            #print("Trigger created successfully.")
            trigger_id = update_result["result"]
            return trigger_id
    except Exception as e:
        print(f"Failed to create trigger: {e}")
        return False


def get_hostgroup_id(hostgroup_name):
    get_hostgroup_id_payload = {
        "jsonrpc": "2.0",
        "method": "hostgroup.get",
        "params": {
            "output": "extend",
            "filter": {
                "name": [
                    hostgroup_name
                ]
            }
        },
        'auth': auth_token,
        'id': 1,
    }

    try:
        update_response = session.post(zabbix_api_url, json=get_hostgroup_id_payload)
        update_result = update_response.json()
        if 'error' in update_result:
            print(f"Failed to get host group id: {update_result['error']['data']}")
            return False
        else:
            #print("Host Group id got successfully.")
            for hosts in update_result["result"]:
                hostgroupid = hosts["groupid"]
            return hostgroupid
    except Exception as e:
        print(f"Failed to get host group id: {e}")
        return False


def create_new_host(new_host, new_ip, host_organization, mailid):
    
    #check organization is available i.e., it checks with usergroups
    usergroupid = check_usergroup(host_organization)
    if usergroupid == "null":
        #create user group
        usergroupid = create_user_group(host_organization)
        print(f"usergroup id {host_organization}: {usergroupid}")
        #create user role
        rolenamenew = host_organization + "Role"
        userroleid = create_user_role(rolenamenew)
        #print(f"user role id for {rolenamenew}: {userroleid}")
   
        #create new user for this new organization i.e., new user groups
        userName = host_organization + "User"
        passwd = "qazxdr@23"       
        userid = create_user(userroleid, usergroupid, mailid, userName, passwd)

        #create Host group for this new organization i.e., new user groups
        hostgroupname = host_organization
        hostgroupid = create_host_group(hostgroupname)
                   
        #Create new host for monitoring the newly added device.
        host_id = create_hosts(new_host, new_ip, hostgroupid )
        if host_id != "False":
            #print(f"New device: {new_host} successfully added for monitoring")
            #Create a trigger to send alert messages via email when host is having problems .
            triggerName = new_host + "Trigger"
            admingroupid = check_usergroup("Zabbix administrators")
            triggerid = action_trigger(triggerName, host_id, admingroupid)
            #print(f"trigger id for {triggerName} is {triggerid}")
    else:
        #get the hostgroupid
        hostgroup_name = host_organization
        hostgroupid = get_hostgroup_id(hostgroup_name)
        #Create new host for monitoring the newly added device.
                    
        host_id = create_hosts(new_host, new_ip, hostgroupid )
        if host_id != "False":
            #print(f"New device: {new_host} successfully added for monitoring")
            #Create a trigger to send alert messages via email when host is having problems .
            triggerName = new_host + "Trigger"
            admingroupid = check_usergroup("Zabbix administrators")
            triggerid = action_trigger(triggerName, host_id, admingroupid)
            #print(f"trigger id for {triggerName} is {triggerid}")

def get_interface_id(host_id):
    get_interfaceid_payload = {
        'jsonrpc': '2.0',
        "method": "hostinterface.get",
        "params": {
            "output": "extend",
            "hostids": host_id
        },
        'auth': auth_token,
        'id': 1,
    }

    try:
        update_response = session.post(zabbix_api_url, json=get_interfaceid_payload)
        update_result = update_response.json()
        host_interface_id = update_result["result"][0]["interfaceid"]
        #print(f"Host interface id: {host_interface_id}")
        return host_interface_id
    except Exception as e:
        #print(f"Failed to check interface id for host id- {host_id}: {e}")
        return False
    
# Update host interface with the new IP address
def update_ip_address(host_interface_id, new_ip):
    update_ip_payload = {
        'jsonrpc': '2.0',
        'method': 'hostinterface.update',
        'params': {
            'interfaceid': host_interface_id,  # The ID of the host interface you want to update
            'ip': new_ip.split("/")[0],
        },
        'auth': auth_token,
        'id': 1,
    }

    try:
        update_response = session.post(zabbix_api_url, json=update_ip_payload)
        update_result = update_response.json()
        if 'error' in update_result:
            print(f"Failed to update host IP address: {update_result['error']['data']}")
            return False
        else:
            #print("Host IP address updated successfully.")
            return True
    except Exception as e:
        print(f"Failed to update host IP address: {e}")
        return False

def main():
    iteration = True
    while(iteration):
        global reachlink_current_info
        tunnel_ip_info()
        get_host_list()
        is_empty = coll_reachlink_zabbix_info.count_documents({}) == 0
        if is_empty:
            for device in reachlink_current_info:
                print(device)
                new_host = device["hubdevice_name"]
                new_ip = device["hub_dialer_ip"]
                host_organization = device["company_name"]
                mailid = device["username"]
                create_new_host(new_host, new_ip, host_organization, mailid)
        else:
            for device in reachlink_current_info:
                new_device = 1
                for device_zabbix in coll_reachlink_zabbix_info.find({},{'_id':0}):
                    if device['hubdevice_name'] == device_zabbix['Host_name']:
                        new_device = 0
                        if device['hub_dialer_ip'] != device_zabbix['Host_ip']:
                            host_id = device_zabbix['Host_id']
                            new_ip = device['hub_dialer_ip']
                            host_interface_id = get_interface_id(host_id)
                            status = update_ip_address(host_interface_id, new_ip)
                            if status == True:
                                print("New Tunnel IP address updated")
                                filter = {"Host_name": device_zabbix['Host_name']}
                                update = {"$set": {"Host_ip": device['hub_dialer_ip']}}
                                coll_reachlink_zabbix_info.update_one(filter, update)
                            else:
                                print(f"Error in updating Tunnel IP address of host: {device['hub_wan_ip_only']} ")

                if new_device == 1:
                    new_host = device["hubdevice_name"]
                    new_ip = device["hub_dialer_ip"]
                    host_organization = device["company_name"]
                    mailid = device["username"]
                    create_new_host(new_host, new_ip, host_organization, mailid)
        #print("updated successfully")
        iteration = False
        #time.sleep(10)

if __name__ == "__main__":
    main()
            
