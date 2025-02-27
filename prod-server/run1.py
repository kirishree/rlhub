import os
import pymongo
from pymongo.server_api import ServerApi
import json
#os.system("cp views_new.py /etc/reach/reachlink/reach/views.py")
mongo_uri = f"mongodb://cloudetel:Cloudetel0108@185.69.209.245:27017/"
client = pymongo.MongoClient(mongo_uri)
db_tunnel = client["reach_link"]
coll_tunnel_ip = db_tunnel["tunnel_ip"]
coll_hub_info = db_tunnel["hub_info"]
data = []
os.system("cp reachlink_zabbix_hub.py /etc/reach/reachlink/")
os.system("python3 /etc/reach/reachlink/reachlink_zabbix_hub.py")
os.system("systemctl stop reachlink_test")
for device in coll_hub_info.find({},{"_id":0}):
      data.append(device)
with open("/etc/reach/reachlink/total_hubs.json", "w") as f:
       json.dump(data, f)
       f.close()
data = []
for device in coll_tunnel_ip.find({},{"_id":0}):
        data.append(device)
with open("/etc/reach/reachlink/total_branches.json", "w") as f:
        json.dump(data, f)
        f.close()
os.system("systemctl start reachlink_test")