import os
import subprocess
import json
import ipaddress
import requests
import time
from datetime import timedelta
#from decouple import config
from datetime import timedelta
from reportlab.lib.pagesizes import letter, landscape
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,  KeepTogether
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
import numpy as np  # For percentile calculation
# Zabbix API URL
#zabbix_api_url = config('ZABBIX_API_URL')  # Replace with your Zabbix API URL
# Api key
#auth_token = config('ZABBIX_API_TOKEN')
# Zabbix server details
#ZABBIX_WEB_URL=config('ZABBIX_WEB_URL')
#USERNAME=config('USERNAME')
#PASSWORD=config('PASSWORD')
#GRAPH_URL=config('GRAPH_URL')
# Zabbix API URL
zabbix_api_url = "http://185.69.209.251/zabbix/api_jsonrpc.php" # Replace with your Zabbix API URL
zabbix_graph_url = "https://reachlinktest.cloudetel.com/zabbix"
# Api key
auth_token = "de4bc85eca6a76481473f6e4efa71812ee7995c02ace600a62b750bc04841810"
# Zabbix server details
ZABBIX_WEB_URL="https://reachlinktest.cloudetel.com/zabbix/index.php"
USERNAME="Admin"
PASSWORD="zabbix"
GRAPH_URL="https://reachlinktest.cloudetel.com/zabbix/chart2.php"
# Step 1: Login using web form
login_payload = {
    "name": USERNAME,
    "password": PASSWORD,
    "enter": "Sign in"
}

# Create a session
session = requests.Session()

def get_item_id(host_id, name):
    """Fetch item IDs related to bits received/sent."""
    get_item = {
        "jsonrpc": "2.0",
        "method": "item.get",
        "params": {
            "output": ["itemid", "name", "delay"],
            #"output": "extend",
            "hostids": host_id           
        },
        'auth': auth_token,
        'id': 1,
    }
    try:          
        response = session.post(zabbix_api_url, json=get_item)
        result = response.json().get('result', [])        
        items = {} 
        no_samplesperhour = 60        
        for item in result:
            if "Bits" in item["name"] and name.split(":")[0] == item["name"].split(":")[0]:                           
                items.update({item["name"]: item["itemid"]})
                int_interval = item["delay"]
                if "m" in  item["delay"]:   
                    no_samplesperhour = round(60 / int(item["delay"].split('m')[0])) 
                if "s" in item["delay"]:
                    no_samplesperhour = round(3600 / int(item["delay"].split('s')[0]))
        if int_interval == '0':
            int_interval = "1m"
        return items, no_samplesperhour, int_interval        
    except Exception as e:
        print(f"Failed to get item list: {e}")
        return {}, False, False

def get_pingresponse_item_id(host_id, name):
    """Fetch item IDs related to bits received/sent."""
    get_responseitem = {
        "jsonrpc": "2.0",
        "method": "item.get",
        "params": {
            "output": ["itemid", "name", "delay"],
            #"output": "extend",
            "hostids": host_id,
            "search": {
            "key_": "icmp"
            },
        },
        'auth': auth_token,
        'id': 1,        
    }
    try:          
        response = session.post(zabbix_api_url, json=get_responseitem)
        result = response.json().get('result', [])        
        items = {} 
        print(result)
        no_samplesperhour = 60        
        for item in result:
            if "response time" in item["name"].lower():                     
                int_interval = item["delay"]
                if "m" in  item["delay"]:   
                    no_samplesperhour = round(60 / int(item["delay"].split('m')[0])) 
                if "s" in item["delay"]:
                    no_samplesperhour = round(3600 / int(item["delay"].split('s')[0]))
            items.update({item["name"]: item["itemid"]})
        if int_interval == '0':
            int_interval = "1m"
        return items, no_samplesperhour, int_interval        
    except Exception as e:
        print(f"Failed to get item list: {e}")
        return {}, False, False

def get_item_id_ping(host_id):
    """Fetch item IDs related to bits received/sent."""
    get_item = {
        "jsonrpc": "2.0",
        "method": "item.get",
        "params": {
            "output": ["itemid", "name", "delay"],
            "hostids": host_id,
            "search": {
            "key_": "icmppingloss"
            },
        },
        'auth': auth_token,
        'id': 1,
    }
    try:   
        no_samplesperhour = 60       
        response = session.post(zabbix_api_url, json=get_item)        
        itemidping = response.json().get('result', [])[0]["itemid"] 
        delay = response.json().get('result', [])[0]["delay"] 
        int_interval = delay
        if "m" in  delay:   
            no_samplesperhour = round(60 / int(delay.split('m')[0])) 
        if "s" in delay:
            no_samplesperhour = round(3600 / int(delay.split('s')[0]))       
        return itemidping, no_samplesperhour    
    except Exception as e:
        print(f"Failed to get item list: {e}")
    return False, False

def get_item_id_uptime(host_id):
    """Fetch item IDs related to bits received/sent."""
    get_item = {
        "jsonrpc": "2.0",
        "method": "item.get",
        "params": {
        "output": ["lastvalue", "name"],
        "hostids": host_id,        
        "search": {
            "key_": ".uptime"
        },
        "sortfield": "name"
    },
        'auth': auth_token,
        'id': 1,
    }
    try:          
        response = session.post(zabbix_api_url, json=get_item, timeout=10)
        result = response.json().get('result', [])
        uptimevalue = int(result[0]['lastvalue'])
        # Convert to readable format
        uptime_str = str(timedelta(seconds=uptimevalue))
        #items = {item["name"]: item["itemid"] for item in result if "Bits" in item["name"] and name.split(":")[0] in item["name"]}
        print(uptime_str)
        return uptime_str     
    except Exception as e:
        print(f"Failed to get item list: {e}")
        return False

def get_trends(itemid, fromdate, todate):  
    time_from = int(time.mktime(time.strptime(fromdate, "%Y-%m-%d %H:%M:%S")))
    time_to = int(time.mktime(time.strptime(todate, "%Y-%m-%d %H:%M:%S")))
    get_trend = {
        "jsonrpc": "2.0",
        "method": "trend.get",
        "params": {
            "output": "extend",
            "itemids": itemid,
            "time_from": time_from,
            "time_till": time_to
                        
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
        print(f"Failed to get trend: {e}")
        return False   
    
def convert_to_mb(bits):
    """Convert bits to Megabytes (MB)."""
    #return round(int(bits) / (8 * 1024 * 1024), 4)
    return round(int(bits) / (1024 * 1024), 4)

def convert_to_mbps(bits):
    """Convert bits to Megabits per second (Mbit/s)."""
    return round(int(bits) / (1024 * 1024), 4)

def download_graph(graphid, fromdate, todate):
    try:
        login_response = session.post(ZABBIX_WEB_URL, data=login_payload)
        # Check if login was successful
        if "zbx_session" not in session.cookies.get_dict():
            print("Login failed! Check credentials.")
            return False
        print("Login successful! Proceeding to download graph...")
        # Step 2: Fetch the graph image
        params = {
            "graphid": graphid,  # Replace with your graph ID
            "from": fromdate,  # Start time (Unix timestamp)
            "to": todate,  # End time (Unix timestamp)
            "width": 800,
            "height": 400,
            "profileIdx": "web.graphs"
            }
        graph_response = session.get(GRAPH_URL, params=params)
        # Step 3: Save the graph if response is an image
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        graph_filename = f"graph_{timestamp}.png"
        if "image/png" in graph_response.headers.get("Content-Type", ""):
            with open(graph_filename, "wb") as f:
                f.write(graph_response.content)
            print("Graph image downloaded successfully as graph.png")
            return graph_filename
        else:
            print("Failed to retrieve graph. Response:", graph_response.text)
            return False
    except Exception as e:
        print("Execption raised on donload graph", e)
        return False
    
def get_graph_id(host_id, name):    
    get_graphid = {
        "jsonrpc": "2.0",
        "method": "graph.get",
        "params": {
            "output": ["graphid", "name"],
            "hostids": host_id,
            "search": {
                        "name": name
                        },           
        },
        'auth': auth_token,
        'id': 1,
    }
    try:
        update_response = session.post(zabbix_api_url, json=get_graphid)
        update_result1 = update_response.json()
        update_result = update_result1.get('result') 
        #print('graphid',update_result1)       
        if 'error' in update_result:
            print(f"Failed to get item list: {update_result['error']['data']}")
            return False
        else:
            for graphinfo in update_result: 
                if name == graphinfo['name']:      
                    return graphinfo['graphid']
            return False
    except Exception as e:
        print(f"Failed to get Host list: {e}")
        return False   

#print(get_graph_id('10721', 'Interface ether1: Network traffic'))

def graph_create(itemid1, itemid2, itemidping, graphname):
    graph_create = {
        "jsonrpc": "2.0",
        "method": "graph.create",
        "params": {
            "name": graphname,
            "width": 900,
            "height": 200,
            "show_work_period": 0,
            "show_triggers": 0,
            "show_legend": 1,
            "gitems": [
                {
                "itemid": itemid2,
                "color": "C5CAE9",
                "drawtype": 1
                },
                {
                "itemid": itemid1,
                "color": "4000FF",
                "drawtype": 2
                },                
                {
                "itemid": itemidping,
                "color": "FF0000",
                "drawtype": 2
                }
            ]            
        },
        'auth': auth_token,
        'id': 1,
    }
    try:
        response = session.post(zabbix_api_url, json=graph_create)
        graphids = response.json()        
        graphid = graphids["result"]["graphids"][0] 
        return graphid    
    except Exception as e:
        print(f"Failed to get create graph: {e}")
        return False

def graph_create_ping(itemid_ping, itemid_loss, itemid_responsetime, graphname):
    graph_create = {
        "jsonrpc": "2.0",
        "method": "graph.create",
        "params": {
            "name": graphname,
            "width": 900,
            "height": 200,
            "show_work_period": 0,
            "show_triggers": 0,
            "show_legend": 1,
            "gitems": [
                {
                "itemid": itemid_responsetime,
                "color": "C5CAE9",
                "drawtype": 1
                },
                {
                "itemid": itemid_loss,
                "color": "FF0000",
                "drawtype": 2
                }             
                
            ]            
        },
        'auth': auth_token,
        'id': 1,
    }
    try:
        response = session.post(zabbix_api_url, json=graph_create)
        graphids = response.json()        
        graphid = graphids["result"]["graphids"][0] 
        return graphid    
    except Exception as e:
        print(f"Failed to get create graph: {e}")
        return False

def graph_delete(graphid):
    graph_delete = {
        "jsonrpc": "2.0",
        "method": "graph.delete",
        "params": [
                    graphid
                    
                ],
        'auth': auth_token,
        'id': 1,
    }
    try:
        response = session.post(zabbix_api_url, json=graph_delete)
        graphids = response.json()        
        graphid = graphids["result"]["graphids"][0] 
        return graphid    
    except Exception as e:
        print(f"Failed to delete graph: {e}")
        return False
    
def get_percentile(itemid_ping, itemid_loss, itemid_responsetime, no_intfcsamplesperinterval, no_icmpsamplesperinterval, interval, fromdate):     
    get_history = {
        "jsonrpc": "2.0",
        "method": "history.get",
        "params": {
            "output": "extend",  
            "history": 0,                 
            "itemids": [itemid_responsetime],            
            "time_from": int(fromdate),
            "time_till": int(fromdate) + interval
        },
        'auth': auth_token,
        'id': 1,
    }
    get_history_loss = {
        "jsonrpc": "2.0",
        "method": "history.get",
        "params": {
            "output": "extend",    
            "history": 0,              
            "itemids": [itemid_loss],            
            "time_from": int(fromdate),
            "time_till": int(fromdate) + interval
        },
        'auth': auth_token,
        'id': 1,
    }
    try:
        response = session.post(zabbix_api_url, json=get_history)
        if itemid_loss:
            responseloss = session.post(zabbix_api_url, json=get_history_loss)
            history_loss = responseloss.json().get('result')            
            pingvalues = []  
            for history_los in history_loss:
                if history_los["itemid"] == itemid_loss:                   
                    pingvalues.append(int(float(history_los["value"])))
        history_results = response.json().get('result')    
        #print("historyresults", response.json())    
        responsevalues = []     
        for history_result in history_results:
            if history_result["itemid"] == itemid_responsetime:
                responsevalues.append(round(float(history_result["value"]), 4))                 
        
        if len(responsevalues) > 0:
            response_value_avg = round(np.mean(responsevalues), 4)
            response_value_max = round(np.max(responsevalues), 4)
            response_value_min = round(np.min(responsevalues), 4)            
            response_percentile = round(np.percentile(responsevalues, 95), 4)                 
            coverage = round((len(responsevalues)/no_intfcsamplesperinterval) * 100, 4)  
            if itemid_loss:                
                responsecount = np.sum(pingvalues)
                #print(responsecount)
                downtime = 0
                if len(pingvalues) > 0:
                    downtime = round((responsecount/len(pingvalues)), 4)
            else:
                downtime = round((100 - coverage), 4)
        else:
            response_value_avg = 0
            response_value_max = 0
            response_value_min = 0
            response_percentile = 0
            coverage = 0  
            downtime = 0
            if itemid_loss:
                get_trend = {
                    "jsonrpc": "2.0",
                    "method": "trend.get",
                    "params": {
                        "output": "extend",
                        "itemids": [itemid_responsetime, itemid_loss],            
                        "time_from": int(fromdate),
                        "time_till": int(fromdate) + interval
                    },
                    'auth': auth_token,
                    'id': 1,
                }
            else:
                get_trend = {
                    "jsonrpc": "2.0",
                    "method": "trend.get",
                    "params": {
                        "output": "extend",
                        "itemids": [itemid_responsetime],            
                        "time_from": int(fromdate),
                        "time_till": int(fromdate) + interval
                    },
                    'auth': auth_token,
                    'id': 1,
                }
            try:
                response = session.post(zabbix_api_url, json=get_trend)
                trend_results = response.json().get('result')                
                for trend_result in trend_results:
                    coverage = round((int(trend_result["num"])/60) * 100, 4)
                    downtime = round((100 - coverage), 4)                    
                    if trend_result["itemid"] == itemid_responsetime:
                        #print("received", trend_result["value_avg"])
                        response_value_avg = round(float(trend_result["value_avg"]), 4)
                        response_value_max = round(float(trend_result["value_max"]), 4)
                        response_value_min = round(float(trend_result["value_min"]), 4)
                        response_percentile = round(float(trend_result["value_max"]), 4)
                    if trend_result["itemid"] == itemid_loss:
                        print("trenddown time", no_icmpsamplesperinterval, trend_result["num"] )
                        downtime = round( ( (no_icmpsamplesperinterval-int(trend_result["num"])) /no_icmpsamplesperinterval) * 100, 4)
                
            except Exception as e:
                print("Error in trend data")                
        percentile_result = {"response_value_avg": response_value_avg,
                             "response_value_max": response_value_max,
                             "response_value_min": response_value_min,
                             "response_percentile": response_percentile,                             
                             "coverage": coverage,
                             "downtime": downtime}
        return percentile_result
    except Exception as e:
        print(f"Failed to get History: {e}")
        return []

def save_to_pdf_ping(intfcname, itemid_ping, itemid_loss, itemid_reponsetime, branch_location, fromdate, todate, graphname, uptime_str, interval, interface_samplesperhr, snmp_interval, filename="traffic_data.pdf", logo_path="logo.png"):
    """Generate a well-structured PDF report with logo, traffic data, and percentile details."""

    custom_width = 1000  # Example: Set to your desired width in points
    custom_height = 612  # Keep letter height or modify
    # Define PDF document with margins
    doc = SimpleDocTemplate(filename, pagesize=(custom_width, custom_height),
                            leftMargin=50, rightMargin=40, topMargin=40, bottomMargin=40)
    elements = []

    # Get styles for headings
    styles = getSampleStyleSheet()
    
    # **Add Logo** (Ensure 'logo.png' is in the same directory)
    try:
        img = Image(logo_path, width=100, height=50)  # Adjust size as needed
        elements.append(img)
        elements.append(Spacer(1, 10))  # Space below logo
    except:
        print("Logo not found, continuing without it.")

    # **Title & Subtitle**
    title = Paragraph(f"<b>Report for {intfcname}</b>", styles["Title"])
    title2 = Paragraph(f"<b>{branch_location}</b>", styles["Title"])
    subtitle = Paragraph(f"<b>Generated on:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]) 

    # Table Header
    data = [["Date Time", "Ping Time(msec)", "Minimum(msec)", 
             "Maximum(msec)", "Packet Loss", "Percentile", "Coverage", "Downtime"]]

    response_avg_values = []
    response_max_values = []
    response_min_values = []
    response_percentiles = []
    total_coverages = []
    downtimes = []
    time_from = int(time.mktime(time.strptime(fromdate, "%Y-%m-%d %H:%M:%S")))
    time_to = int(time.mktime(time.strptime(todate, "%Y-%m-%d %H:%M:%S")))
    no_intfcsamples_interval = round( ( (interface_samplesperhr * interval) / 3600 ) )
    print("samples", no_intfcsamples_interval)
    no_icmpsamples_interval = no_intfcsamples_interval
    # Add data rows
    for time_from in range(time_from, time_to, interval):
        time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(time_from)))
        percentile_output = get_percentile(itemid_ping, itemid_loss, itemid_reponsetime, no_intfcsamples_interval, no_icmpsamples_interval, interval, time_from)
        response_value_avg = percentile_output["response_value_avg"]
        response_value_max = percentile_output["response_value_max"]
        response_value_min = percentile_output["response_value_min"]
        response_percentile = percentile_output["response_percentile"]
        coverage = percentile_output["coverage"]
        downtime = percentile_output["downtime"]
        
        # Store values for percentile calculation
        response_avg_values.append(response_value_avg)
        response_max_values.append(response_value_max)
        response_min_values.append(response_value_min)
        response_percentiles.append(response_percentile)
        total_coverages.append(coverage)         
        downtimes.append(downtime)
        row = [time_str, response_value_avg, response_value_min, response_value_max, "-", response_percentile, coverage, downtime]
        data.append(row)

    # Calculate 95th percentile
    
    avg_ = round(np.mean(response_avg_values), 4)  
    min_ = round(np.mean(response_min_values), 4)  
    max_ = round(np.mean(response_max_values), 4)  
    percentile = round(np.percentile(response_percentiles, 95), 4)
     
    avg_coverage = round(np.mean(total_coverages), 4)
    avg_downtime = round(np.mean(downtimes), 4)
    
    # Table Header
    data1 = [["Date Time", "Ping Time(msec)", "Minimum(msec)", 
             "Maximum(msec)", "Packet Loss", "Percentile", "Coverage", "Downtime"]]
    
    
    data1.append([f"Averages(of {len(response_avg_values)}) values", avg_, min_, 
                  max_, "-", percentile, avg_coverage, avg_downtime])
    # Append 95th percentile row to table
    #data.append(["95th Percentile", in_95th, "-", out_95th, "-", total_95th, "-"])
    # Set column widths to fit within the page
    column_widths = [110, 90, 90, 90, 90, 90, 90, 90]

    # Create the table with defined column widths
    table = Table(data, colWidths=column_widths)
    # Create the table with defined column widths
    tableconsolidated = Table(data1, colWidths=column_widths)
    # Add table styles
    tableconsolidated.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),  # Header background color
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  # Header text color
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),  # Adjust font size for better fit
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),  # Grid for table
        #('BACKGROUND', (0, -1), (-1, -1), colors.lightgrey),  # 95th percentile row highlight
        #('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
    ]))
    # Add table styles
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),  # Header background color
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  # Header text color
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),  # Adjust font size for better fit
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),  # Grid for table
        #('BACKGROUND', (0, -1), (-1, -1), colors.lightgrey),  # 95th percentile row highlight
        #('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
    ]))      
    uptime_percentage = round((100-avg_downtime), 4)
    # Table Header
    datainfo = [["Report Time Span:", f"{fromdate} - {todate}"]]
    datainfo = [["Sensor Type:", f"Ping ({snmp_interval} interval)"]]
    datainfo.append(["Uptime stats:", f"UP:  {uptime_percentage}%  [{uptime_str}]  Down:  {avg_downtime}%"])
    datainfo.append(["Average(Ping Time):", f"{str(avg_)} msec"])    
    datainfo.append(["Percentile:", f"{str(percentile)} msec"])
    columninfo_widths = [150, 300]
    tableinfo = Table(datainfo, colWidths=columninfo_widths)    
    # Add table styles
    tableinfo.setStyle(TableStyle([       
 
        ('FONTSIZE', (0, 0), (-1, -1), 12),  # Adjust font size for better fit
        #('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        #('GRID', (0, 0), (-1, -1), 1, colors.whitesmoke),  # Grid for table
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('LINEBELOW', (0, 0), (-1, -1), 3, colors.whitesmoke),
        
    ]))
    elements.append(title)
    elements.append(Spacer(1, 12))  # Space
    elements.append(title2)
    elements.append(Spacer(1, 12))  # Space
    elements.append(subtitle)
    elements.append(Spacer(1, 12))  # Space
    tableinfo.hAlign = 'LEFT'  # Ensure table is aligned to the left
    elements.append(tableinfo)
    elements.append(Spacer(1, 12))  # More space before the image 
      
    try:
        graphimg = Image(graphname, width=500, height=200)  # Adjust size as needed
        graphimg.hAlign = 'LEFT'  # Ensure image is aligned to the left

        elements.append(Spacer(1, 12))  # Ensure spacing before adding the image
        elements.append(graphimg)
        elements.append(Spacer(1, 40))  # Space below the image
    except:
        print("Graph not found, continuing without it.")
    tableconsolidated.hAlign = 'LEFT'  # Ensure table is aligned to the left
    elements.append(tableconsolidated)
    elements.append(Spacer(1, 12))  # More space before the table
    table.hAlign = 'LEFT'  # Ensure table is aligned to the left
    elements.append(table)
    # Build PDF
    doc.build(elements)
    print(f"Traffic data saved to {filename}")

def ping_report_gen(data):
    try:        
        hostid = data["hostid"]
        intfcname = data["intfcname"]
        fromdate = data["fromdate"]
        todate = data["todate"]
        ishub = data["ishub"]         
        interval = int(data.get("interval", 3600))
        if ishub:
            branch_location = "HUB Location: " + data["branch_location"]
        else:
            branch_location = "Branch Location: " + data["branch_location"]        
        #item_ids, interface_sampesperhr, snmp_interval = get_item_id(hostid, intfcname)        
        item_ids, interface_sampesperhr, snmp_interval = get_pingresponse_item_id(hostid, intfcname) 
        if not item_ids:
            print("No relevant items found.")            
            response = [{"message": "No relevant items found.", "status": False}]            
            return response
        for name, itemid in item_ids.items():
            if "loss" in name.lower():
                itemid_icmploss = itemid                
            if "response" in name:
                itemid_responsetime = itemid 
            if "ping" in name:
                itemid_icmpping = itemid        
        #itemidping, icmp_samplesperhr = get_item_id_ping(hostid)
        graphname = "Ping"     
        graphid = get_graph_id(hostid, graphname) 
         
        if not graphid:
            graphid = graph_create_ping(itemid_icmpping, itemid_icmploss, itemid_responsetime,  graphname)
        if graphid: 
            download_graph_name = download_graph(graphid, fromdate, todate)
            #graph_delete(graphid)
            if(download_graph_name):
                    uptime_str = get_item_id_uptime(hostid)                    
                    save_to_pdf_ping(intfcname,
                                     itemid_icmpping, 
                                     itemid_icmploss, 
                                     itemid_responsetime,
                                     branch_location, 
                                     fromdate, todate, 
                                     download_graph_name,                                    
                                     uptime_str, 
                                     interval, 
                                     interface_sampesperhr, 
                                     snmp_interval
                                     ) 
                    os.system(f"rm -r {download_graph_name}")     
                    return {"message": "Traffic data generated successfully.", "status": True}
            else:            
                return {"message": "Error Issue to get Graph.", "status": False}
        else:            
            return {"message": "Error Issue to create Graph.", "status": False}
    except Exception as e:
        print(f"Error: {e}")        
        response = {"message": "Error Internal server problem.", "status": False}    
    return response


#10727
data6 = {'hostid': '10731', 'intfcname': 'ICMP Response time', 
        'branch_location': 'jeddah', 'fromdate': '2025-04-04 02:11:00', 
        'todate': '2025-04-04 12:26:00', 'ishub': True, 'interval': 1800}
print(ping_report_gen(data6))