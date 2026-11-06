import os
import subprocess
import pymongo
from pymongo.server_api import ServerApi
import time
import json
from decouple import config
mongo_username = config('REACH_DB_USERNAME')
mongo_password = config('REACH_DB_PASSWORD')
hub_ip = config('HUB_IP')
mongo_uri = f"mongodb://{mongo_username}:{mongo_password}@{hub_ip}:27017/"
client = pymongo.MongoClient(mongo_uri)
db_tunnel = client["reach_link"]
coll_tunnel_ip = db_tunnel["tunnel_ip"]

data = []
for device in coll_tunnel_ip.find({},{"_id":0}):
        data.append(device)
with open("total_branches.json", "w") as f:
        json.dump(data, f)
        f.close()
