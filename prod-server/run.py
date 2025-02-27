import os
import pymongo
from pymongo.server_api import ServerApi
import json
mongo_uri = f"mongodb://cloudetel:Cloudetel0108@185.69.209.245:27017/"
client = pymongo.MongoClient(mongo_uri)
db_tunnel = client["reach_link"]
coll_tunnel_ip = db_tunnel["tunnel_ip"]
coll_hub_info = db_tunnel["hub_info"]
os.system("cp reachlink_test.service /etc/systemd/system/")
os.system("cp gunicorn_reachlink.service /etc/systemd/system/")
os.system("cp reachlink_zabbix_hub.py /etc/reach/reachlink/")
os.system("cp reachlink_zabbix.py /etc/reach/reachlink/")
os.system("cp router_configure.py /etc/reach/reachlink/")
os.system("cp microtek_configure.py /etc/reach/reachlink/")
os.system("cp robustel_configure.py /etc/reach/reachlink/")
os.system("cp onboarding.py /etc/reach/reachlink/")
os.system("cp onboardblock.py /etc/reach/reachlink/")
os.system("cp hub_config.py /etc/reach/reachlink/")
os.system("cp ubuntu_info.py /etc/reach/reachlink/")
os.system("cp views_new.py /etc/reach/reachlink/reach/views.py")
os.system("cp urls_new.py /etc/reach/reachlink/reachlink/urls.py")
os.system("systemctl restart reachlink_test")
os.system("cp reachlinkst.py /etc/reach/reachlink/")
os.system("cp reachlink_config.exe /etc/reach/reachlink/")
os.system("cp reachlink_hub_config.exe /etc/reach/reachlink/")
os.system("cp robustel_conf.exe /etc/reach/reachlink/")
os.system("cp .env.sh /etc/reach/reachlink/.env")
os.system("cp pon.txt /etc/reach/reachlink/")