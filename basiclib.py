from django.http import HttpRequest, HttpResponse,  JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from django_ratelimit.decorators import ratelimit
import logging
logger = logging.getLogger(__name__)
import os
import subprocess
import json
import ipaddress
import pymongo
from pymongo.server_api import ServerApi
import reachlinkst
import requests
import uuid
from datetime import datetime
from dateutil.relativedelta import relativedelta
from pyroute2 import IPRoute
ipr = IPRoute()
from netaddr import IPAddress
import psutil
import socket
import threading
import random
import router_configure
import microtek_configure
import time
import yaml
import string
import io
import zipfile
import base64
import re
#import the files
import onboarding
import hub_config
import ubuntu_info
from decouple import config
resource_active = True
resource_inactive = True
newuser = False
dummy_expiry_date = ""
mongo_uri = config('DB_CONNECTION_STRING')
client = pymongo.MongoClient(mongo_uri)
db_tunnel = client["reach_link"]
coll_registered_organization = db_tunnel["registered_organization"]
coll_tunnel_ip = db_tunnel["tunnel_ip"]
coll_spoke_active = db_tunnel["spoke_active"]
coll_spoke_inactive = db_tunnel["spoke_inactive"]
coll_spoke_disconnect = db_tunnel["spoke_disconnect"]
coll_deleted_organization = db_tunnel["deleted_organization"]
coll_dialer_ip = db_tunnel["dialer_ip"]
coll_hub_info = db_tunnel["hub_info"]
vrf1_ip = '10.200.202.0/24'
url = "https://dev-api.cloudetel.com/api/v1/"
hub_ip = config('HUB_IP')
hub_location = "jeddah"
hub_uuid = "reachlinkserver.net"
hub_hostid = "10084"
gretunnelnetwork = "10.200.202.0/24"
gretunnelnetworkip = "10.200.202."
hub_tunnel_endpoint = "10.200.202.2"
openvpnhubip = "10.8.0.1"
dialernetworkip = config('DIALER_NERWORK_IP')
cisco_dialer_hub_ip = config('DIALER_HUB_IP')
cisco_hub_username = config('DIALER_HUB_USERNAME')
cisco_hub_password = config('DIALER_HUB_PASSWORD')
dialer_netmask = config('DIALER_NETMASK')
snmpcommunitystring = "reachlink"
ubuntu_dialerclient_ip = config('UBUNTU_DIALER_CLIENT_IP')
