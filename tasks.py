from celery import shared_task
import pymongo
from decouple import config
import os
import subprocess
import logging
logger = logging.getLogger('reachlink')
mongo_uri = config('DB_CONNECTION_STRING')
client = pymongo.MongoClient(mongo_uri)
db_tunnel = client["reach_link"]
coll_tunnel_ip = db_tunnel["tunnel_ip"]
coll_registered_organization = db_tunnel["registered_organization"]
reachlink_zabbix_path = config('REACHLINK_ZABBIX_PATH')

@shared_task(bind=True, max_retries=20, default_retry_delay=60)
def setass_task(self, response, devicename):   
    try:
        connected_spoke =[]
        newspokedevicename = response[0]["spokedevice_name"]        
        newspokeconnstatus = False
        with open(r'/etc/openvpn/server/openvpn-status.log','r') as f:
            lines = f.readlines()
            for row in  lines:     
                data=row.split(",")
                if data[0] == "CLIENT_LIST":
                    collection = {"Tunnel_ip":data[3], "Public_ip":data[2].split(":")[0], "spokedevice_name": data[1]}
                    connected_spoke.append(collection) 
        for spoke in connected_spoke:
            if spoke["spokedevice_name"] == newspokedevicename:
                if devicename == "microtek":
                    query = {"spokedevice_name": newspokedevicename }
                    update_data = {"$set": {"public_ip":spoke["Public_ip"],
                                            "tunnel_ip": spoke["Tunnel_ip"]                                                                       
                                        }
                                       }
                    newspokeconnstatus = True    
                    coll_tunnel_ip.update_many(query, update_data) 
                    organizationid = response[0]["organization_id"]
                    regdevices = coll_registered_organization.find_one({"organization_id":organizationid}) 
                    for dev in regdevices["registered_devices"]:                    
                        if "microtek_spokes_info" in dev:                             
                                for mispoke in  dev["microtek_spokes_info"]:                         
                                    if newspokedevicename == mispoke["spokedevice_name"]:
                                        mispoke["tunnel_ip"] = spoke["Tunnel_ip"] 
                                        mispoke["public_ip"] = spoke["Public_ip"]                                 
                                        
                    query = {"organization_id": organizationid}
                    update_data = {"$set": {
                                        "registered_devices": regdevices["registered_devices"]                                                                           
                                        }
                                       }
                    coll_registered_organization.update_many(query, update_data)   
                elif devicename == "robustel":
                    query = {"spokedevice_name": newspokedevicename }
                    update_data = {"$set": {"public_ip":spoke["Public_ip"],
                                            "tunnel_ip": spoke["Tunnel_ip"]                                                                       
                                        }
                                       }
                    newspokeconnstatus = True    
                    coll_tunnel_ip.update_many(query, update_data) 
                    organizationid = response[0]["organization_id"]
                    regdevices = coll_registered_organization.find_one({"organization_id":organizationid}) 
                    for dev in regdevices["registered_devices"]:                    
                        if "robustel_spokes_info" in dev:                             
                                for rospoke in  dev["robustel_spokes_info"]:                         
                                    if newspokedevicename == rospoke["spokedevice_name"]:
                                        rospoke["tunnel_ip"] = spoke["Tunnel_ip"] 
                                        rospoke["public_ip"] = spoke["Public_ip"]                               
                                        
                    query = {"organization_id": organizationid}
                    update_data = {"$set": {
                                        "registered_devices": regdevices["registered_devices"]                                                                           
                                        }
                                       }
                    coll_registered_organization.update_many(query, update_data)                                  
                else:
                    newspokeovpnip = spoke["Tunnel_ip"]
                    newspokeconnstatus = True
                    newspokegreip = response[0]["gretunnel_ip"].split("/")[0]
                    command = f"sudo ip neighbor replace {newspokegreip} lladdr {newspokeovpnip} dev Reach_link1"
                    subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                    query = {"spokedevice_name": newspokedevicename }
                    update_data = {"$set": {"public_ip":newspokeovpnip                                                                         
                                        }
                                       }
                    coll_tunnel_ip.update_many(query, update_data)
                os.system(f"python3 {reachlink_zabbix_path}")
                os.system("systemctl restart reachlink_test")                           
        if not newspokeconnstatus:
            print(f"New spoke is not connected yet({newspokedevicename}). Trying again")
            logger.error(
                        f"New spoke is not connected yet({newspokedevicename}). Trying again",
                        extra={
                            "device_type": devicename,
                            "device_ip": newspokedevicename,
                            "api_endpoint": "celery_task",
                            "exception": ""
                        }
            )    
            raise self.retry(exc=Exception("Spoke not connected yet"))
        else:
            print(f"Tunnel connected successfully for this {newspokedevicename}")
            logger.info(
                        f"Tunnel connected successfully for this {newspokedevicename}",
                        extra={
                            "device_type": devicename,
                            "device_ip": newspokedevicename,
                            "api_endpoint": "celery_task",
                            "exception": ""
                        }
            ) 
    except Exception as e:
        logger.error(
                        str(e),
                        extra={
                            "device_type": devicename,
                            "device_ip": response,
                            "api_endpoint": "celery_task",
                            "exception": str(e)
                        }
            ) 
        print(f"set ass execption:{e}")
