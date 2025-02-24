import os
import pymongo
from pymongo.server_api import ServerApi
import json
os.system("cp robustel_configure.py /root/reachlink/")
os.system("cp views_new.py /root/reachlink/reach/views.py")
os.system("cp conf/dist/robustel_conf.exe /root/reachlink/")
os.system("cp conf/dist/reachlink_config.exe /root/reachlink/")
os.system("cp conf/dist/reachlink_hub_config.exe /root/reachlink/")
#os.system("cp reachlinkst.py /root/reachlink/")
#os.system("systemctl restart reachlink_test")