from datetime import datetime
from dateutil.relativedelta import relativedelta
import pymongo
from decouple import config
import onboarding
import random 
import string 
import router_configure
import ipaddress
mongo_uri = config('DB_CONNECTION_STRING')
client = pymongo.MongoClient(mongo_uri)
db_tunnel = client["reach_link"]
coll_registered_organization = db_tunnel["registered_organization"]
coll_hub_info = db_tunnel["hub_info"]
coll_dialer_ip = db_tunnel["dialer_ip"]

dialernetworkip = config('DIALER_NERWORK_IP')
snmpcommunitystring = config('SNMP_COMMUNITY_STRING')
hub_ip = config('HUB_IP')

def get_ciscohub_config(data):  
    current_datetime = datetime.now()
    try:
        organization_id, data1 = onboarding.get_organization_id(data)
        print("orgid", organization_id)  
        if organization_id:            
            details = coll_registered_organization.find_one({"organization_id":organization_id})
            if details:                                                   
                if current_datetime < details["subscription_to"]:
                    registered_devices_info = details["registered_devices"]                  
                    for device in registered_devices_info:
                        if device['uuid'] == data["uuid"]:  
                            hubinfo = coll_hub_info.find_one({"uuid": data["uuid"]})
                            if hubinfo:
                                response ={ "message": 'This device is already Registered',
                                            "interface_wan_ip":hubinfo["hub_wan_ip_only"],
                                            "interface_wan_netmask":hubinfo["hub_wan_ip_netmask"],
                                            "interface_wan_gateway":hubinfo["hub_wan_ip_gateway"],
                                            "dialernetwork": hubinfo["hub_dialer_network"],
                                            "dialernetmask": hubinfo["hub_dialer_netmask"],
                                            "dialerhubip": hubinfo["hub_dialer_ip"],
                                            "ubuntuhubip": hub_ip,
                                            "router_username": hubinfo["router_username"],
                                            "router_password": hubinfo["router_password"],
                                            "snmpcommunitystring": snmpcommunitystring,
                                            }
                                return response
                    response = {"message": "This HUB location was not configuared yet."}
                else:
                    response = {"message": "Your subscription was expired. Kindly renew it"} 
            else:
                response = {"message": "This organization is not registered with ReachLink"} 
        else:
            response = {"message": "This username is not registered with CloudEtel"} 
    except Exception as e:
        print(f"Exception while get_hub_config end point: {e}")
        response = {"message": "Some internal error. Pl try again"}
    return response

def get_ciscospoke_config(data):
    current_datetime = datetime.now()
    try:
        organization_id, data1 = onboarding.get_organization_id(data)
        print("orgid", organization_id)  
        if organization_id:            
            details = coll_registered_organization.find_one({"organization_id":organization_id})
            if details:                                                   
                if current_datetime < details["subscription_to"]:
                    registered_devices_info = details["registered_devices"]                  
                    for device in registered_devices_info:
                        if device['uuid'] == data["uuid"]:  
                            spokeinfo = coll_dialer_ip.find_one({"uuid": data["uuid"]})
                            if spokeinfo:
                                response ={ "message": 'This device is already Registered',
                                            "interface_wan_ip": spokeinfo["router_wan_ip_only"],
                                            "interface_wan_netmask":spokeinfo["router_wan_ip_netmask"],
                                            "dialerserverip":spokeinfo["dialer_hub_ip"],
                                            "interface_wan_gateway": spokeinfo["router_wan_ip_gateway"],
                                            "dialer_client_ip": spokeinfo["dialerip"],
                                            "dialer_netmask": spokeinfo["hub_dialer_netmask"],
                                            "dialer_username": spokeinfo["dialerusername"],
                                            "dialer_password": spokeinfo["dialerpassword"],
                                            "router_username": spokeinfo["router_username"],
                                            "router_password": spokeinfo["router_password"],
                                            "hub_dialer_network": spokeinfo["hub_dialer_network"],
                                            "hub_dialer_wildcardmask": spokeinfo["hub_dialer_wildcardmask"],
                                            "ubuntu_dialerclient_ip": spokeinfo["ubuntu_dialerclient_ip"],
                                            "snmpcommunitystring": snmpcommunitystring,
                                            }
                                return response
                    response = {"message": "This Branch location was not configuared yet."}
                else:
                    response = {"message": "Your subscription was expired. Kindly renew it"} 
            else:
                response = {"message": "This organization is not registered with ReachLink"} 
        else:
            response = {"message": "This username is not registered with CloudEtel"} 
    except Exception as e:
        print(f"Exception while get_hub_config end point: {e}")
        response = {"message": "Some internal error. Pl try again"}
    return response

def generate_dialer_password():
    # Define character pools
    char_pool = ""
    char_pool += string.ascii_lowercase
    char_pool += string.digits
    if not char_pool:
        raise ValueError("At least one character type must be selected.")
    # Ensure the password contains at least one character of each selected type
    password = []
    password.append(random.choice(string.ascii_lowercase))
    password.append(random.choice(string.digits))
    password.append('@')
    # Fill the rest of the password length with random choices
    remaining_length = 8 - len(password)
    password.extend(random.choices(char_pool, k=remaining_length))    
    # Shuffle the password to avoid predictable patterns
    random.shuffle(password)    
    return ''.join(password)

def generate_dialerip(dialerips):
    random_no = random.randint(3,250)
    newdialerip = dialernetworkip + str(random_no)
    for dialerip in dialerips:
        if dialerip == newdialerip:
            return generate_dialerip(dialerips)
    return newdialerip

def get_dialer_ip(devicename):
    try:
        with open("/etc/ppp/chap-secrets", "r") as f:
            chapsecret = f.read()
            f.close()
        usernames = []
        dialer_ips = []
        newdialerip = False
        newdialerpassword = False
        chapsecrets = chapsecret.split("\n")
        for sec in chapsecrets:
            if "#" not in sec:
                username = sec.strip().split(" ")[0]
                usernames.append(username)
                if username == devicename:
                    print("User Already available")
                    dialerip = sec.strip().split(" ")[-1]
                    dialerpassword= sec.strip().split(" ")[2]
                    return ({"dialerip":dialerip,
                             "dialerpassword": dialerpassword,
                             "dialerusername": devicename,
                             "message": "olduser"})                    
                dialer_ips.append(sec.strip().split(" ")[-1])
        newdialerip = generate_dialerip(dialer_ips)
        newdialerpassword = generate_dialer_password()
        with open("/etc/ppp/chap-secrets", "a") as f:
            f.write(f'\n{devicename}   *   {newdialerpassword}    {newdialerip}\n')
            f.close()
        #os.system("systemctl restart pptpd")
        return ({"dialerip":newdialerip,
                "dialerpassword": newdialerpassword,
                "dialerusername": devicename,
                "message": "newuser"})        
    except Exception as e:
        print(e)
    return ({"dialerip":newdialerip,
                "dialerpassword": newdialerpassword,
                "dialerusername": devicename,
                "message": "error"})             
               
def generate_dialerip_cisco(networkip, netmaskip, hubdialerip):
    network = ipaddress.IPv4Network(f"{networkip}/{netmaskip}", strict=False)
    excluded_ips = {dialerin["dialerip"] for dialerin in coll_dialer_ip.find({}, {"_id": 0})}
    excluded_ips.add(hubdialerip) 
    while True:
        newdialerip = str(random.choice(list(network.hosts())[1:]))
        if newdialerip not in excluded_ips:
            break
    return newdialerip

def generate_dialer_password_cisco():
    # Define character pools
    char_pool = ""
    char_pool += string.ascii_lowercase
    char_pool += string.digits
    if not char_pool:
        raise ValueError("At least one character type must be selected.")
    # Ensure the password contains at least one character of each selected type
    password = []
    password.append(random.choice(string.ascii_lowercase))
    password.append(random.choice(string.digits))
    password.append('@')
    # Fill the rest of the password length with random choices
    remaining_length = 8 - len(password)
    password.extend(random.choices(char_pool, k=remaining_length))
    
    # Shuffle the password to avoid predictable patterns
    random.shuffle(password)    
    return ''.join(password)

def get_dialer_ip_fromciscohub(devicename, dialerip):
    try:
        
        newdialerpassword = generate_dialer_password_cisco()
        hub_info = coll_hub_info.find_one({"hub_wan_ip_only": dialerip})       
        if hub_info:
            newdialerip = generate_dialerip_cisco(hub_info["hub_dialer_network"], hub_info["hub_dialer_netmask"], hub_info["hub_dialer_ip"])            
            if (router_configure.adduser({"username":devicename,
                                  "password":newdialerpassword,
                                  "tunnel_ip": dialerip,
                                "router_username": hub_info["router_username"],
                                "router_password": hub_info["router_password"]})):   
                return ({"dialerip":newdialerip,
                            "dialerpassword": newdialerpassword,
                            "dialerusername": devicename,
                            "hub_dialer_network":hub_info["hub_dialer_network"],
                            "hub_dialer_netmask":hub_info["hub_dialer_netmask"]
                        })        
    except Exception as e:
        print(e)
    return False



def generate_router_password_cisco():
    # Define character pools
    char_pool = ""
    char_pool += string.ascii_lowercase
    char_pool += string.digits
    if not char_pool:
        raise ValueError("At least one character type must be selected.")

    # Ensure the password contains at least one character of each selected type
    password = []
    password.append(random.choice(string.ascii_lowercase))
    password.append(random.choice(string.digits))
    password.append('@')
    # Fill the rest of the password length with random choices
    remaining_length = 8 - len(password)
    password.extend(random.choices(char_pool, k=remaining_length))
    
    # Shuffle the password to avoid predictable patterns
    random.shuffle(password)    
    return ''.join(password)
