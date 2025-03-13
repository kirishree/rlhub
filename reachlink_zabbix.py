import requests
import json
import pymongo
import time
from decouple import config
hub_ip = config('HUB_IP')
mongo_uri = config('DB_CONNECTION_STRING')
client = pymongo.MongoClient(mongo_uri)
db = client["reach_link"]
coll_reachlink_zabbix_info = db["reachlink_zabbix_info"]
coll_tunnel_ip = db["tunnel_ip"]
coll_registered_organization = db["registered_organization"]
rlserver_wan_intfc = config('RLSERVER_WAN_INTFC')
# Zabbix API URL
zabbix_api_url = config('ZABBIX_API_URL')  # Replace with your Zabbix API URL

# Api key
auth_token = config('ZABBIX_API_TOKEN')

# Create a session
session = requests.Session()
reachlink_current_info = []

def get_item_id(host_id, name):    
    get_item = {
        "jsonrpc": "2.0",
        "method": "item.get",
        "params": {
            "output": ["itemid", "name"],
            "hostids": host_id,
            "search": {
                        "name": name
                        },           
        },
        'auth': auth_token,
        'id': 1,
    }
    try:
        update_response = session.post(zabbix_api_url, json=get_item)
        update_result1 = update_response.json()
        update_result = update_result1.get('result')
        if 'error' in update_result:
            print(f"Failed to get item list: {update_result['error']['data']}")
            return False
        else:            
            return update_result
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
def create_hosts(new_host, new_ip, hostgroupid, templateid):
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
                    "templateid":templateid
				
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
            filter = {"tunnel_ip": new_ip}
            update = {"$set": {"host_id": host_id}}
            coll_tunnel_ip.update_one(filter, update)       
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


def create_new_host(new_host, new_ip, host_organization, mailid, templateid):
    
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
        host_id = create_hosts(new_host, new_ip, hostgroupid, templateid )
        if host_id != "False":
            #print(f"New device: {new_host} successfully added for monitoring")
            #Create a trigger to send alert messages via email when host is having problems .
            triggerName = new_host + "Trigger"
            admingroupid = check_usergroup("Zabbix administrators")
            triggerid = action_trigger(triggerName, host_id, admingroupid)
            #print(f"trigger id for {triggerName} is {triggerid}")
        return host_id
    else:
        #get the hostgroupid
        hostgroup_name = host_organization
        hostgroupid = get_hostgroup_id(hostgroup_name)
        #Create new host for monitoring the newly added device.
                    
        host_id = create_hosts(new_host, new_ip, hostgroupid, templateid )
        if host_id != "False":
            #print(f"New device: {new_host} successfully added for monitoring")
            #Create a trigger to send alert messages via email when host is having problems .
            triggerName = new_host + "Trigger"
            admingroupid = check_usergroup("Zabbix administrators")
            triggerid = action_trigger(triggerName, host_id, admingroupid)
            #print(f"trigger id for {triggerName} is {triggerid}")
        return host_id


def main():
    iteration = True
    try:        
        registered_organization = list(coll_registered_organization.find({}))
        for reg_org in registered_organization:
            devices = reg_org["registered_devices"]
            for users in reg_org["regusers"]:
                if users["username"] != "none":
                    mailid = users['username']  
                    break
            for device in devices:
                if "reachlink_hub_info" in device:
                    if "host_id" in device["reachlink_hub_info"]:
                        print("Already host_id available")
                    else:                                                      
                        templateid = "10248"
                        host_id = create_new_host("reachlinkserver", hub_ip, reg_org["organization_name"], mailid, templateid)
                        device["reachlink_hub_info"]["host_id"] = host_id   
                    if "itemid_sent" in device["reachlink_hub_info"]:
                        print("Already item_id available")
                    else: 
                        if "host_id" in device["reachlink_hub_info"]:                                                
                            item_id = get_item_id(device["reachlink_hub_info"]["host_id"], f"Interface {rlserver_wan_intfc}: Bits")
                            print("itemid...", item_id)
                            for item in item_id:
                                if "sent" in item["name"]:
                                    device["reachlink_hub_info"]["itemid_sent"] = item["itemid"] 
                                if "received" in item["name"]:
                                    device["reachlink_hub_info"]["itemid_received"] = item["itemid"]                                             
                        
                if "microtek_spokes_info" in device:
                    for mispoke in device["microtek_spokes_info"]:
                        if "host_id" in mispoke:
                            print("Already host_id available")
                        else: 
                            print(mispoke) 
                            if mispoke.get("tunnel_ip", "None") != "None":                                                
                                templateid = "10248"
                                host_id = create_new_host(mispoke["spokedevice_name"], mispoke["tunnel_ip"], reg_org["organization_name"], mailid, templateid)
                                mispoke["host_id"] = host_id
                        if "itemid_sent" in mispoke:
                            print("Already item_id available")
                        else: 
                            if "host_id" in mispoke:                                                
                                item_id = get_item_id(mispoke["host_id"], "Interface ether1(): Bits")
                                for item in item_id:
                                    if "sent" in item["name"]:
                                        mispoke["itemid_sent"] = item["itemid"] 
                                    if "received" in item["name"]:
                                        mispoke["itemid_received"] = item["itemid"]   
                        
                if "robustel_spokes_info" in device:
                    for rospoke in device["robustel_spokes_info"]:
                        if "host_id" in rospoke:
                            print("Already host_id available")
                        else:
                            if rospoke.get("tunnel_ip", "None") != "None":                                                       
                                templateid = "10248"
                                host_id = create_new_host(rospoke["spokedevice_name"], rospoke["tunnel_ip"], reg_org["organization_name"], mailid, templateid)
                                rospoke["host_id"] = host_id
                        if "itemid_sent" in rospoke:
                            print("Already item_id available")
                        else: 
                            if "host_id" in rospoke:                                                
                                item_id = get_item_id(rospoke["host_id"], "Interface eth0: Bits")
                                for item in item_id:
                                    if "sent" in item["name"]:
                                        rospoke["itemid_sent"] = item["itemid"] 
                                    if "received" in item["name"]:
                                        rospoke["itemid_received"] = item["itemid"]   
                if "cisco_spokes_info" in device:
                    for cispoke in device["cisco_spokes_info"]:
                        if "host_id" in cispoke:
                            print("Already host_id available")
                        else: 
                            if cispoke.get("dialerip", "None") != "None":                                                       
                                templateid = "10218"
                                host_id = create_new_host(cispoke["spokedevice_name"], cispoke["dialerip"], reg_org["organization_name"], mailid, templateid)
                                cispoke["host_id"] = host_id
                        if "itemid_sent" in cispoke:
                            print("Already item_id available")
                        else: 
                            if "host_id" in cispoke:                                                
                                item_id = get_item_id(cispoke["host_id"], "Interface Fa4(): Bits")
                                for item in item_id:
                                    if "sent" in item["name"]:
                                        cispoke["itemid_sent"] = item["itemid"] 
                                    if "received" in item["name"]:
                                        cispoke["itemid_received"] = item["itemid"]   
                if "ubuntu_spokes_info" in device:
                    for ubspoke in device["ubuntu_spokes_info"]:
                        if "host_id" in ubspoke:
                            print("Already host_id available")
                        else:     
                            if ubspoke.get("tunnel_ip", "None") != "None":                                                  
                                templateid = "10248"
                                host_id = create_new_host(ubspoke["spokedevice_name"], ubspoke["tunnel_ip"], reg_org["organization_name"], mailid, templateid)
                                ubspoke["host_id"] = host_id
                        if "itemid_sent" in ubspoke:
                            print("Already item_id available")
                        else: 
                            if "host_id" in ubspoke:                                                
                                item_id = get_item_id(ubspoke["host_id"], "Interface eth0: Bits")
                                for item in item_id:
                                    if "sent" in item["name"]:
                                        ubspoke["itemid_sent"] = item["itemid"] 
                                    if "received" in item["name"]:
                                        ubspoke["itemid_received"] = item["itemid"]   
                if "cisco_hub_info" in device:
                    if "host_id" in device["cisco_hub_info"]:
                        print("Already host_id available")
                    else:     
                        if device["cisco_hub_info"]["hub_wan_ip_only"] != "None":                                                    
                            templateid = "10218"
                            host_id = create_new_host(device["cisco_hub_info"]["spokedevice_name"], device["cisco_hub_info"]["hub_wan_ip_only"], reg_org["organization_name"], mailid, templateid)
                            device["cisco_hub_info"]["host_id"] = host_id   
                    if "itemid_sent" in device["cisco_hub_info"]:
                        print("Already item_id available")
                    else: 
                        if "host_id" in device["cisco_hub_info"]:                                                
                            item_id = get_item_id(device["cisco_hub_info"]["host_id"], "Interface Fa4(): Bits")
                            for item in item_id:
                                if "sent" in item["name"]:
                                    device["cisco_hub_info"]["itemid_sent"] = item["itemid"] 
                                if "received" in item["name"]:
                                    device["cisco_hub_info"]["itemid_received"] = item["itemid"] 
                    
                query = {"organization_id": reg_org["organization_id"]}
                update_data = {"$set": {"registered_devices": devices                                                                            
                                        }
                                }
                coll_registered_organization.update_many(query, update_data) 
    except Exception as e:
        print(e)               
if __name__ == "__main__":
    main()    
            
