import os
import pymongo
from pymongo.server_api import ServerApi
import json
mongo_uri = f"mongodb://cloudetel:Cloudetel0108@185.69.209.251:27017/"
client = pymongo.MongoClient(mongo_uri)
db_tunnel = client["reach_link"]
coll_tunnel_ip = db_tunnel["tunnel_ip"]
coll_hub_info = db_tunnel["hub_info"]
data = []
#os.system("systemctl stop reachlink_test")
#for device in coll_hub_info.find({},{"_id":0}):
#       data.append(device)
#with open("/root/reachlink/total_hubs.json", "w") as f:
#        json.dump(data, f)
#       f.close()
#data = []
#for device in coll_tunnel_ip.find({},{"_id":0}):
#        data.append(device)
#with open("/root/reachlink/total_branches.json", "w") as f:
#        json.dump(data, f)
#        f.close()
os.system("cp views_hub.py /root/reachlink/reach/views.py")
os.system("cp com_router_config.py /root/reachlink/")
os.system("cp urls_hub.py /root/reachlink/reachlink/urls.py")
os.system("cp reachlinkst.py /root/reachlink/")
#os.system("systemctl restart reachlink_test")
os.system("cp reachlink_config.exe /root/reachlink/")
os.system("cp reachlink_hub_config.exe /root/reachlink/")