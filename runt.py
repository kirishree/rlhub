import os
import pymongo
from pymongo.server_api import ServerApi
import json
os.system("cp robustel_configure.py /root/reachlink/")
os.system("cp router_configure.py /root/reachlink/")

os.system("cp onboarding.py /root/reachlink/")
os.system("cp microtek_configure.py /root/reachlink/")
os.system("cp ubuntu_info.py /root/reachlink/")
os.system("cp hub_config.py /root/reachlink/")
#os.system("cp reachlinkst.py /root/reachlink/reachlinkst.py")
#os.system("cp logo.png /root/reachlink/")
#os.system("cp urls_new2.py /root/reachlink/reachlink/urls.py")
#os.system("cp conf/dist/robustel_conf.exe /root/reachlink/")
os.system("cp reachlink_zabbix.py /root/reachlink/")
os.system("cp conf/dist/reachlink_hub_config.exe /root/reachlink/")
#os.system("cp reachlinkst.py /root/reachlink/")
#os.system("systemctl restart reachlink_test")
#os.system("cp conf/dist/reachlink_cisco_config.exe /root/reachlink/")
os.system("cp zabbix_gen_report.py /root/reachl" \
"ink/")
os.system("cp zabbix_ping_report.py /root/reachlink/")
os.system("cp conf/dist/* /root/reachlink/")
os.system("cp tasks.py /root/reachlink/reach/")
#os.system("cp views_new.py /root/reachlink/reach/views.py")
os.system("cp views_swagger.py /root/reachlink/reach/views.py")
os.system("cp serializers.py /root/reachlink/reach/")
os.system("cp test_views.py /root/reachlink/reach/tests/")
os.system("cp conftest.py /root/reachlink/reach/tests/")
os.system("cp urls_swagger.py /root/reachlink/reachlink/urls.py")
os.system("systemctl restart reachlink_be")
os.system("systemctl restart celery")
