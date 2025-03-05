import requests
import json


# Zabbix API URL
zabbix_api_url = 'http://185.69.209.251/zabbix/api_jsonrpc.php'  # Replace with your Zabbix API URL

# Zabbix API credentials
username = 'Admin'
password = 'zabbix'

# Api key
auth_token = "de4bc85eca6a76481473f6e4efa71812ee7995c02ace600a62b750bc04841810"

# Create a session
session = requests.Session()

def get_host_list():
    
    get_item = {
        "jsonrpc": "2.0",
        "method": "item.get",
        "params": {
            "output": ["itemid", "name", "hostid"],
            "hostids": ["10677","10658"],
            "search": {
                        "name": "Interface Fa4(): Bits"
                        },
           
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
            data = []
            print(update_result)
            print("hii")
            for itemid in update_result:
                get_history = {
                    "jsonrpc": "2.0",
                    "method": "history.get",
                    "params": {
                                "output": "extend",
                                
                                "itemids": itemid["itemid"],
                                "sortfield": "clock",
                                "sortorder": "DESC",
                                "limit": 1
                    },
                    'auth': auth_token,
                    'id': 1,
                } 
                try:
                    history_response = session.post(zabbix_api_url, json=get_history)
                    history_result1 = history_response.json()
                    history_result = history_result1.get('result')
                    print(history_result1)
                    if 'error' in history_result:
                        print(f"Failed to get item list: {update_result['error']['data']}")
                        return False
                    else:
                        data.append({"name":itemid["name"],
                                     "value":history_result[0]["value"],
                                     "hostid": itemid["hostid"],
                                     "clock": history_result[0]["clock"]})
                except Exception as e:
                    print(e)   
            print(data) 
            return True     
    except Exception as e:
        print(f"Failed to get Host list: {e}")
        return False   

def main():
    
    get_host_list()
if __name__ == "__main__":
    main()