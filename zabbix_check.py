import requests
import time
import json
import os
import subprocess
# Zabbix API URL
zabbix_api_url = "http://185.69.209.251/zabbix/api_jsonrpc.php" # Replace with your Zabbix API URL
# Api key
auth_token = "de4bc85eca6a76481473f6e4efa71812ee7995c02ace600a62b750bc04841810"
# Create a session
session = requests.Session()

def get_host_id(host_name):
    get_hostid = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "output": ["hostid", "status"],            
            "filter": {
                "host": [
                    host_name
                ]
            }      
        },
        'auth': auth_token,
        'id': 1,
    }
    try:
        update_response = session.post(zabbix_api_url, json=get_hostid)
        update_result1 = update_response.json()
        update_result = update_result1.get('result')
        if 'error' in update_result:
            print(f"Failed to get host id: {update_result['error']['data']}")
            return False
        else:            
            return update_result
    except Exception as e:
        print(f"Failed to get Host list: {e}")
        return False   

def get_item_id(host_id, name):    
    get_item = {
        "jsonrpc": "2.0",
        "method": "item.get",
        "params": {
            "output": ["itemid", "name"],
            "hostids": host_id,
                   
        },
        'auth': auth_token,
        'id': 1,
    }
    try:
        update_response = session.post(zabbix_api_url, json=get_item)
        update_result1 = update_response.json()
        update_result = update_result1.get('result')
        if 'error' in update_result:
            print(f"Failed to get item list: {update_result['error']['data']}")
            return False
        else:            
            return update_result
    except Exception as e:
        print(f"Failed to get Host list: {e}")
        return False   

def get_history(itemid): 
    time_from = int(time.mktime(time.strptime("2025-03-15 00:00:00", "%Y-%m-%d %H:%M:%S")))
    time_to = int(time.mktime(time.strptime("2025-03-18 00:00:00", "%Y-%m-%d %H:%M:%S")))
    print("time from", time_from)
    print("time to", time_to)
    get_history = {
        "jsonrpc": "2.0",
        "method": "history.get",
        "params": {
            "output": "extend",
            "itemids": itemid,
            "sortfield": "clock",
            "sortorder": "DESC",
            "time_from": time_from,
            "time_till": time_to
        },
        'auth': auth_token,
        'id': 1,
    }
    try:
        history_response = session.post(zabbix_api_url, json=get_history)
        history_result1 = history_response.json()
        history_result = history_result1.get('result')
        if 'error' in history_result:
            print(f"Failed to get item list: {history_result['error']['data']}")
            return False
        else:
            return history_result                    
    except Exception as e:
        print(f"Failed to get History: {e}")
        return False   
    
def get_trends(itemid): 
    time_from = int(time.mktime(time.strptime("2025-03-15 00:00:00", "%Y-%m-%d %H:%M:%S")))
    time_to = int(time.mktime(time.strptime("2025-03-18 00:00:00", "%Y-%m-%d %H:%M:%S")))
    print("time from", time_from)
    print("time to", time_to)
    get_trend = {
        "jsonrpc": "2.0",
        "method": "trend.get",
        "params": {
            "output": "extend",
            "itemids": "55433"            
        },
        'auth': auth_token,
        'id': 1,
    }
    try:
        trend_response = session.post(zabbix_api_url, json=get_trend)
        trend_result1 = trend_response.json()
        trend_result = trend_result1.get('result')
        if 'error' in trend_result:
            print(f"Failed to get item list: {trend_result['error']['data']}")
            return False
        else:
            return trend_result                    
    except Exception as e:
        print(f"Failed to get History: {e}")
        return False   
    
def main():
    try:
        hostid = get_host_id("DUBAI-UAE")[0]["hostid"]
        itemid_info = get_item_id(hostid, "Interface")
        for items in itemid_info:
            if "Bits" in items["name"]:
                #trafficdata = get_history(items["itemid"])
                trafficdata = get_trends(items["itemid"])
                for trend in trafficdata:
                    trend["clock"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(trend["clock"])))
                print(trafficdata)
                break
    except Exception as e:
        print(e)

if __name__ == "__main__":
    main()