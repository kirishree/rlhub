import requests
import time
import json
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
import numpy as np  # For percentile calculation
from datetime import timedelta
import os
# Zabbix server details
ZABBIX_WEB_URL="https://reachlinktest.cloudetel.com/zabbix/index.php"
USERNAME="Admin"
PASSWORD="zabbix"
GRAPH_URL="https://reachlinktest.cloudetel.com/zabbix/chart2.php"
# Start a session to maintain cookies
session = requests.Session()

# Step 1: Login using web form
login_payload = {
    "name": USERNAME,
    "password": PASSWORD,
    "enter": "Sign in"
}
# Zabbix API URL
zabbix_api_url = "http://185.69.209.251/zabbix/api_jsonrpc.php" # Replace with your Zabbix API URL
zabbix_graph_url = "https://reachlinktest.cloudetel.com/zabbix"
# Api key
auth_token = "de4bc85eca6a76481473f6e4efa71812ee7995c02ace600a62b750bc04841810"
# Create a session
session = requests.Session()


def get_host_id(host_name):
    """Fetch the host ID for a given host name."""
    get_hostid = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "output": ["hostid"],
            "filter": {"host": [host_name]}
        },
        'auth': auth_token,
        'id': 1,
    }
    try:
        response = session.post(zabbix_api_url, json=get_hostid)
        result = response.json().get('result', [])
        return result[0]["hostid"] if result else None
    except Exception as e:
        print(f"Failed to get Host ID: {e}")
        return None

def get_item_id(host_id, name):
    """Fetch item IDs related to bits received/sent."""
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
        response = session.post(zabbix_api_url, json=get_item)
        result = response.json().get('result', [])
        items = {item["name"]: item["itemid"] for item in result if "Bits" in item["name"] and name.split(":")[0] in item["name"]}
        return items        
    except Exception as e:
        print(f"Failed to get item list: {e}")
        return {}

def get_item_id_ping(host_id):
    """Fetch item IDs related to bits received/sent."""
    get_item = {
        "jsonrpc": "2.0",
        "method": "item.get",
        "params": {
            "output": ["itemid", "name"],
            "hostids": host_id,
            "search": {
            "key_": "icmpping"
            },
        },
        'auth': auth_token,
        'id': 1,
    }
    try:          
        response = session.post(zabbix_api_url, json=get_item)
        result = response.json().get('result', [])
        items = {item["name"]: item["itemid"] for item in result if "ping" in item["name"]}
        return items         
    except Exception as e:
        print(f"Failed to get item list: {e}")
        return False
    
print(get_item_id_ping("10677"))

def get_item_id_uptime(host_id):
    """Fetch item IDs related to bits received/sent."""
    get_item = {
        "jsonrpc": "2.0",
        "method": "item.get",
        "params": {
        "output": ["lastvalue", "name"],
        "hostids": host_id,        
        "search": {
            "key_": "system.net.uptime"
        },
        "sortfield": "name"
    },
        'auth': auth_token,
        'id': 1,
    }
    try:          
        response = session.post(zabbix_api_url, json=get_item)
        result = response.json().get('result', [])
        uptimevalue = result[0]['lastvalue']
        # Convert to readable format
        uptime_str = str(timedelta(seconds=uptimevalue))
        #items = {item["name"]: item["itemid"] for item in result if "Bits" in item["name"] and name.split(":")[0] in item["name"]}
        return uptime_str     
    except Exception as e:
        print(f"Failed to get item list: {e}")
        return False

def get_percentile(itemidsent, itemidreceived, fromdate):
    print("hi")
    get_history = {
        "jsonrpc": "2.0",
        "method": "history.get",
        "params": {
            "output": "extend",
            "history": 0,
            "itemids": [itemidsent, itemidreceived, "52628"],            
            "time_from": int(fromdate),
            "time_till": int(fromdate) + 3600
        },
        'auth': auth_token,
        'id': 1,
    }
    try:
        response = session.post(zabbix_api_url, json=get_history)
        history_results = response.json().get('result')
        sentvalues = []
        receivedvalues = []
        totalvalues = []
        for history_result in history_results:
            if history_result["itemid"] == itemidsent:
                sentvalues.append(int(history_result["value"]))
            if history_result["itemid"] == itemidreceived:
                receivedvalues.append(int(history_result["value"]))
        for i in range(0,len(sentvalues)):            
            total = sentvalues[i] + receivedvalues[i] 
            totalvalues.append(total)           
        
        if len(totalvalues) > 0:
            in_value_avg = round(np.mean(sentvalues), 4)
            out_value_avg = round(np.mean(receivedvalues), 4)
            total_value_avg = round(np.mean(totalvalues), 4)
            in_percentile = round(np.percentile(sentvalues, 95), 4)
            out_percentile = round(np.percentile(receivedvalues, 95), 4)            
            total_percentile = round(np.percentile(totalvalues, 95), 4)
            coverage = round((len(totalvalues)/60) * 100, 4)           
            
        else:
            print(history_results)
            in_value_avg = 0
            out_value_avg = 0
            total_value_avg = 0
            in_percentile = 0
            out_percentile = 0
            total_percentile = 0
            coverage = 0  
        percentile_result = {"in_avg":in_value_avg,
                             "in_percentile": in_percentile,
                             "out_avg": out_value_avg,
                             "out_percentile": out_percentile,
                             "total_avg": total_value_avg,
                             "total_percentile": total_percentile,
                             "coverage": coverage}
        return percentile_result
    except Exception as e:
        print(f"Failed to get History: {e}")
        return []

def get_history(itemid):
    """Fetch historical traffic data (bits received/sent) for the last 3 days."""
    time_from = int(time.mktime(time.strptime("2025-03-15 00:00:00", "%Y-%m-%d %H:%M:%S")))
    time_to = int(time.mktime(time.strptime("2025-03-18 00:00:00", "%Y-%m-%d %H:%M:%S")))

    get_history = {
        "jsonrpc": "2.0",
        "method": "history.get",
        "params": {
            "output": ["clock", "value"],
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
        response = session.post(zabbix_api_url, json=get_history)
        return response.json().get('result', [])
    except Exception as e:
        print(f"Failed to get History: {e}")
        return []

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
    
def graph_create(itemid1, itemid2, fromdate, todate, graphname):
    graph_create = {
        "jsonrpc": "2.0",
        "method": "graph.create",
        "params": {
            "name": graphname,
            "width": 900,
            "height": 200,
            "show_work_period": 0,
            "show_triggers": 0,
            "gitems": [
                {
                "itemid": itemid1,
                "color": "1a2856",
                "drawtype": 1
                },
                {
                "itemid": itemid2,
                "color": "c8262b",
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
#fromdate = "2025-03-27 11:00:00"
#todate = "2025-03-28 10:00:00"
#print(get_trends("57212", fromdate, todate))
def convert_to_mb(bits):
    """Convert bits to Megabytes (MB)."""
    #return round(int(bits) / (8 * 1024 * 1024), 4)
    return round(int(bits) / (1024 * 1024), 4)

def convert_to_mbps(bits):
    """Convert bits to Megabits per second (Mbit/s)."""
    return round(int(bits) / (1024 * 1024), 4)

def save_to_pdf(intfcname, branch_location, fromdate, todate, graphname, itemidreceived, itemidsent, filename="traffic_data.pdf", logo_path="logo.png"):
    """Generate a well-structured PDF report with logo, traffic data, and percentile details."""

    # Define PDF document with margins
    doc = SimpleDocTemplate(filename, pagesize=letter,
                            leftMargin=20, rightMargin=20, topMargin=40, bottomMargin=40)
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
    data = [["Date Time", "Traffic In(Mbit/s)", "Traffic In(MB)", 
             "Traffic Out(Mbit/s)", "Traffic Out(MB)", "Traffic Total(Mbit/s)", "Traffic Total(MB)", "Percentile", "Coverage"]]

    in_avg_values = []
    out_avg_values = []
    total_speed_values = []
    total_volumes = []
    total_coverages = []
    in_volumes = []
    out_volumes = []
    time_from = int(time.mktime(time.strptime(fromdate, "%Y-%m-%d %H:%M:%S")))
    time_to = int(time.mktime(time.strptime(todate, "%Y-%m-%d %H:%M:%S")))
    # Add data rows    
    for time_from in range(time_from, time_to, 3600):
        time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(time_from)))
        percentile_output = get_percentile(itemidsent, itemidreceived, time_from)
        in_speed = convert_to_mbps(int(percentile_output["in_avg"]))
        out_speed = convert_to_mbps(int(percentile_output["out_avg"]))
        coverage = percentile_output["coverage"]
        in_volume = round((in_speed * 180) / (8), 4)
        out_volume = round((out_speed * 180) / (8), 4)
        total_speed = round(in_speed + out_speed, 4)
        total_volume = round(in_volume + out_volume, 4)
        print("check", percentile_output["total_percentile"])
        total_percentile = convert_to_mbps(percentile_output["total_percentile"])     
        # Store values for percentile calculation
        in_avg_values.append(in_speed)
        out_avg_values.append(out_speed)
        total_speed_values.append(total_speed)
        total_volumes.append(total_volume)  
        total_coverages.append(coverage) 
        in_volumes.append(in_volume) 
        out_volumes.append(out_volume)
        row = [time_str, in_speed, in_volume, out_speed, out_volume, total_speed, total_volume, total_percentile, coverage]
        data.append(row)

    # Calculate 95th percentile
    in_95th = round(np.percentile(in_avg_values, 95), 4)    
    out_95th = round(np.percentile(out_avg_values, 95), 4)
    total_95th = round(np.percentile(total_speed_values, 95), 4)
    avg_speed = round(np.mean(total_speed_values), 4)  # Average
    total_traffic = round(np.sum(total_volumes), 4)  # Total
    percentile = round(np.percentile(total_speed_values, 95), 4)
    avg_in_speed = round(np.mean(in_avg_values), 4)
    avg_out_speed = round(np.mean(out_avg_values), 4)    
    avg_coverage = round(np.mean(total_coverages), 4)
    total_in_volumes = round(np.sum(in_volumes), 4)
    total_out_volumes = round(np.sum(out_volumes), 4)
    # Table Header
    data1 = [["Date Time", "Traffic In(Mbit/s)", "Traffic In(MB)", 
             "Traffic Out(Mbit/s)", "Traffic Out(MB)", "Traffic Total(Mbit/s)", "Traffic Total(MB)", "Percentile", "Coverage"]]

    data1.append([f"Sums(of {len(total_volumes)}) values", " ", total_in_volumes, 
                  " ", total_out_volumes, " ", total_traffic, " " , " "])
    
    data1.append([f"Averages(of {len(total_volumes)}) values", avg_in_speed, " ", 
                  avg_out_speed, " ", avg_speed, " ", " " , avg_coverage])
    # Append 95th percentile row to table
    #data.append(["95th Percentile", in_95th, "-", out_95th, "-", total_95th, "-"])

    # Set column widths to fit within the page
    column_widths = [110, 70, 60, 70, 65, 70, 70, 50, 50]
    # Create the table with defined column widths
    table = Table(data, colWidths=column_widths)
    # Create the table with defined column widths
    tableconsolidated = Table(data1, colWidths=column_widths)
    # Add table styles
    # Add table styles
    tableconsolidated.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),  # Header background color
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  # Header text color
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),  # Adjust font size for better fit
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),  # Grid for table
        #('BACKGROUND', (0, -1), (-1, -1), colors.lightgrey),  # 95th percentile row highlight
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
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
        ('GRID', (0, 0), (-1, -1), 1, colors.black),  # Grid for table
        #('BACKGROUND', (0, -1), (-1, -1), colors.lightgrey),  # 95th percentile row highlight
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
    ]))
    totaltraffic = Paragraph(f"<b>Traffic Total: {str(total_traffic)} MB</b>", styles["Normal"])
    avgspeed = Paragraph(f"<b>Average Speed: {str(avg_speed)} Mbit/s</b>", styles["Normal"])
    percentilestr = Paragraph(f"<b>Percentile: {str(percentile)} Mbit/s</b>", styles["Normal"])
    duration = Paragraph(f"<b>Duration: {fromdate} to {todate} </b>", styles["Normal"])
    elements.append(title)
    elements.append(Spacer(1, 12))  # Space
    elements.append(title2)
    elements.append(Spacer(1, 12))  # Space
    elements.append(subtitle)
    elements.append(Spacer(1, 12))  # Space
    elements.append(duration)
    elements.append(Spacer(1, 12))  # Space
    elements.append(totaltraffic)
    elements.append(Spacer(1, 12))  # Space
    elements.append(avgspeed)
    elements.append(Spacer(1, 12))  # Space
    elements.append(percentilestr)
    elements.append(Spacer(1, 12))  # More space before the table
    # **Add Logo** (Ensure 'logo.png' is in the same directory)
    try:
        graphimg = Image(graphname, width=500, height=200)  # Adjust size as needed
        elements.append(graphimg)
        elements.append(Spacer(1, 20))  # Space below logo
    except:
        print("Logo not found, continuing without it.")
    elements.append(tableconsolidated)
    elements.append(Spacer(1, 12))  # More space before the table
    elements.append(table)

    # Build PDF
    doc.build(elements)

    print(f"Traffic data saved to {filename}")

def main():
    try:
        #hostid = get_host_id("DUBAI-UAE")
        hostid = "10677"
        intfcname = "Interface Fa4(): Network traffic"
        branch_location = "Jeddah Cisco HUB"
        fromdate = "2025-03-27 10:00:00"
        todate = "2025-03-28 12:00:00"
        if not hostid:
            print("Host ID not found.")
            return

        item_ids = get_item_id(hostid, intfcname)
        get_item_id_uptime(hostid) 
        print(item_ids)
        if not item_ids:
            print("No relevant items found.")
            return
        for name, itemid in item_ids.items():
            if "received" in name:
                itemidreceived = itemid                
            if "sent" in name:
                itemidsent = itemid        
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        graphname = f"graph_{timestamp}"     
        graphid = graph_create(itemidsent, itemidreceived, fromdate, todate, graphname)
        if graphid:
            download_graph_name = download_graph(graphid, fromdate, todate)
            graph_delete(graphid)
            if(download_graph_name):                
                save_to_pdf(intfcname, branch_location, fromdate, todate, download_graph_name, itemidreceived, itemidsent)
                #save_to_pdf(intfcname, branch_location, fromdate, todate, download_graph_name, "53268", "53157")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
