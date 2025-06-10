import os
import pymongo
from pymongo.server_api import ServerApi
import json
os.system("cp hub_config.py /etc/reach/reachlink/")
os.system("cp logo.png /etc/reach/reachlink/")
os.system("cp microtek_configure.py /etc/reach/reachlink/")
os.system("cp onboardblock.py /etc/reach/reachlink/")
os.system("cp onboarding.py /etc/reach/reachlink/")
os.system("cp pon.txt /etc/reach/reachlink/")
os.system("cp reachlink_zabbix.py /etc/reach/reachlink/")
os.system("cp reachlinkst.py /etc/reach/reachlink/")
os.system("cp robustel_configure.py /etc/reach/reachlink/")
os.system("cp router_configure.py /etc/reach/reachlink/")
os.system("cp ubuntu_info.py /etc/reach/reachlink/")
os.system("cp urls_new.py /etc/reach/reachlink/reachlink/urls.py")
os.system("cp views.py /etc/reach/reachlink/reach/views.py")
os.system("cp zabbix_gen_report.py /etc/reach/reachlink/")
os.system("cp zabbix_ping_report.py /etc/reach/reachlink/")
os.system("cp confp/dist/* /etc/reach/reachlink/")
os.system("systemctl restart reachlink_test")
os.system("cp tasks.py /etc/reach/reachlink/reach/")
os.system("systemctl restart reachlink_be")
os.system("systemctl restart celery")