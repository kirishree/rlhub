import os
import subprocess
import json
import ipaddress
import requests
import time
from datetime import timedelta
from decouple import config
from datetime import timedelta
from reportlab.lib.pagesizes import letter, landscape
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,  KeepTogether
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Flowable
from reportlab.lib.units import mm
import numpy as np  # For percentile calculation
zabbix_api_url = config('ZABBIX_API_URL')  # Replace with your Zabbix API URL
auth_token = config('ZABBIX_API_TOKEN')
ZABBIX_WEB_URL=config('ZABBIX_WEB_URL') # Zabbix server details
USERNAME=config('USERNAME')
PASSWORD=config('PASSWORD')
GRAPH_URL=config('GRAPH_URL')
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
        print(f"Failed to get item id: {e}")
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
        print(f"Failed to get icmp loss item id: {e}")
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
        for item in result:
            if "network" in item["name"].lower():
                uptimevalue = int(item['lastvalue'])                    
                uptime_str = str(timedelta(seconds=uptimevalue))  # Convert to readable format              
                print(uptime_str)
                return uptime_str     
    except Exception as e:
        print(f"Failed to get uptime item id: {e}")
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
            print(f"Graph image downloaded successfully as {graph_filename}")
            return graph_filename
        else:
            print("Failed to retrieve graph. Response:", graph_response.text)
            return False
    except Exception as e:
        print("Execption raised on download graph", e)
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
        if 'error' in update_result:
            print(f"Failed to get graph id: {update_result['error']['data']}")
            return False
        else:
            for graphinfo in update_result: 
                if name == graphinfo['name']:      
                    return graphinfo['graphid']
            return False
    except Exception as e:
        print(f"Failed to get graph id: {e}")
        return False   

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
    
def get_percentile(itemidsent, itemidreceived, itemidping, no_intfcsamplesperinterval, no_icmpsamplesperinterval, interval, fromdate):     
    global total_ping_loss
    get_history = {
        "jsonrpc": "2.0",
        "method": "history.get",
        "params": {
            "output": "extend",                  
            "itemids": [itemidsent, itemidreceived],            
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
            "itemids": [itemidping],            
            "time_from": int(fromdate),
            "time_till": int(fromdate) + interval
        },
        'auth': auth_token,
        'id': 1,
    }
    try:
        response = session.post(zabbix_api_url, json=get_history)
        if itemidping:
            responseloss = session.post(zabbix_api_url, json=get_history_loss)
            history_loss = responseloss.json().get('result')
            pingvalues = []  
            consecutive_loss = 0
            downtime_interval = 0
            for history_los in history_loss:
                if history_los["itemid"] == itemidping:                   
                    pingvalues.append(int(float(history_los["value"])))
                    if consecutive_loss == 5:
                        downtime_interval +=1
                    if int(float(history_los["value"])) == 100:
                        consecutive_loss += 1
                        total_ping_loss += 1
                    else:
                        consecutive_loss = 0      
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
            coverage = round((len(totalvalues)/no_intfcsamplesperinterval) * 100, 4)  
            if itemidping:                
                responsecount = np.sum(pingvalues)
                downtime = 0
                packetloss = 0
                if downtime_interval > 0:
                    downtime = round(( downtime_interval*5 / len(pingvalues) ), 4)  
                if len(pingvalues) > 0:
                    packetloss = round((responsecount/len(pingvalues)), 4)              
            else:
                downtime = round((100 - coverage), 4)
                packetloss = round((100 - coverage), 4)
        else:
            in_value_avg = 0
            out_value_avg = 0
            total_value_avg = 0
            in_percentile = 0
            out_percentile = 0
            total_percentile = 0
            coverage = 0  
            downtime = 0
            packetloss = 0
            if itemidping:
                get_trend = {
                    "jsonrpc": "2.0",
                    "method": "trend.get",
                    "params": {
                        "output": "extend",
                        "itemids": [itemidsent, itemidreceived, itemidping],            
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
                        "itemids": [itemidsent, itemidreceived],            
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
                    if trend_result["itemid"] == itemidsent:
                        in_value_avg = trend_result["value_avg"]
                        in_percentile = trend_result["value_max"]
                    if trend_result["itemid"] == itemidreceived:
                        out_value_avg = trend_result["value_avg"]
                        out_percentile = trend_result["value_max"]
                    if trend_result["itemid"] == itemidping:
                        print("trenddown time", no_icmpsamplesperinterval, trend_result["num"] )
                        downtime = round( ( (no_icmpsamplesperinterval-int(trend_result["num"])) /no_icmpsamplesperinterval) * 100, 4)
                        packetloss = downtime
                total_value_avg = in_value_avg + out_value_avg
                total_percentile = in_percentile + out_percentile
            except Exception as e:
                print(f"Error in trend data:{e}")                
        percentile_result = {"in_avg":in_value_avg,
                             "in_percentile": in_percentile,
                             "out_avg": out_value_avg,
                             "out_percentile": out_percentile,
                             "total_avg": total_value_avg,
                             "total_percentile": total_percentile,
                             "coverage": coverage,
                             "downtime": downtime,
                             "packet_loss": packetloss}
        return percentile_result
    except Exception as e:
        print(f"Failed to get History: {e}")
        return []

class UptimeBar(Flowable):
    def __init__(self, percentage, width=8, height=25):
        Flowable.__init__(self)
        self.percentage = percentage
        self.width = width
        self.height = height

    def draw(self):
        # Draw background (full bar)
        self.canv.setStrokeColor(colors.black)
        self.canv.setFillColor(colors.lightgrey)
        self.canv.rect(0, 0, self.width, self.height, stroke=1, fill=1)

        # Determine fill color based on thresholds
        if self.percentage >= 99.0:
            bar_color = colors.green
        elif self.percentage >= 98.0:
            bar_color = colors.yellow
        else:
            bar_color = colors.red

        # Draw filled portion (from bottom up)
        fill_height = self.height * (self.percentage / 100.0)
        self.canv.setFillColor(bar_color)
        self.canv.rect(0, 0, self.width, fill_height, stroke=0, fill=1)
def save_to_pdf(intfcname, branch_location, fromdate, todate, graphname, itemidreceived, itemidsent, uptime_str, interval, itemidping, interface_samplesperhr, icmp_samplesperhr, snmp_interval, filename, logo_path="logo.png"):
    """Generate a well-structured PDF report with logo, traffic data, and percentile details."""

    custom_width = 1000  # Example: Set to your desired width in points
    custom_height = 612  # Keep letter height or modify
    # Define PDF document with margins
    doc = SimpleDocTemplate(filename, pagesize=(custom_width, custom_height),
                            leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=40)
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
             "Traffic Out(Mbit/s)", "Traffic Out(MB)", "Traffic Total(Mbit/s)", "Traffic Total(MB)", "Percentile(Mbit/s)", "Coverage(%)", "Downtime(%)"]]

    in_avg_values = []
    out_avg_values = []
    total_speed_values = []
    total_volumes = []
    total_coverages = []
    in_volumes = []
    out_volumes = []
    downtimes = []
    time_from = int(time.mktime(time.strptime(fromdate, "%Y-%m-%d %H:%M:%S")))
    time_to = int(time.mktime(time.strptime(todate, "%Y-%m-%d %H:%M:%S")))
    no_intfcsamples_interval = round( ( (interface_samplesperhr * interval) / 3600 ) )
    no_icmpsamples_interval = 60
    if icmp_samplesperhr:
        no_icmpsamples_interval = round( ( (icmp_samplesperhr * interval) / 3600 ) )
     # Polling interval in seconds (1 minute = 60 seconds)
    polling_interval = 60

    # Calculate total polls
    total_polls = (time_to - time_from) // polling_interval
    global total_ping_loss
    total_ping_loss = 0
    # Add data rows
    for time_from in range(time_from, time_to, interval):
        time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(time_from)))
        percentile_output = get_percentile(itemidsent, itemidreceived, itemidping, no_intfcsamples_interval, no_icmpsamples_interval, interval, time_from)
        in_speed = convert_to_mbps(int(percentile_output["in_avg"]))
        out_speed = convert_to_mbps(int(percentile_output["out_avg"]))
        coverage = percentile_output["coverage"]
        in_volume = round((in_speed * 180) / (8), 4)
        out_volume = round((out_speed * 180) / (8), 4)
        total_speed = round(in_speed + out_speed, 4)
        total_volume = round(in_volume + out_volume, 4)
        total_percentile = convert_to_mbps(percentile_output["total_percentile"])
        downtime = percentile_output["downtime"]
        # Store values for percentile calculation
        in_avg_values.append(in_speed)
        out_avg_values.append(out_speed)
        total_speed_values.append(total_speed)
        total_volumes.append(total_volume)  
        total_coverages.append(coverage) 
        in_volumes.append(in_volume) 
        out_volumes.append(out_volume)        
        downtimes.append(downtime)
        row = [time_str, in_speed, in_volume, out_speed, out_volume, total_speed, total_volume, total_percentile, coverage, downtime]
        data.append(row)

    # Calculate 95th percentile
    avg_speed = round(np.mean(total_speed_values), 4)  # Average
    total_traffic = round(np.sum(total_volumes), 4)  # Total
    percentile = round(np.percentile(total_speed_values, 95), 4)
    avg_in_speed = round(np.mean(in_avg_values), 4)
    avg_out_speed = round(np.mean(out_avg_values), 4)    
    avg_coverage = round(np.mean(total_coverages), 4)
    avg_downtime = round(np.mean(downtimes), 4)
    total_in_volumes = round(np.sum(in_volumes), 4)
    total_out_volumes = round(np.sum(out_volumes), 4)
    # Table Header
    data1 = [["Date Time", "Traffic In(Mbit/s)", "Traffic In(MB)", 
             "Traffic Out(Mbit/s)", "Traffic Out(MB)", "Traffic Total(Mbit/s)", "Traffic Total(MB)", "Percentile(Mbit/s)", "Coverage(%)", "Downtime(%)"]]

    data1.append([f"Sums(of {len(total_volumes)}) values", " ", total_in_volumes, 
                  " ", total_out_volumes, " ", total_traffic, " " , " ", " "])
    
    data1.append([f"Averages(of {len(total_volumes)}) values", avg_in_speed, " ", 
                  avg_out_speed, " ", avg_speed, " ", " " , avg_coverage, avg_downtime])
    
    # Set column widths to fit within the page
    column_widths = [110, 90, 90, 90, 90, 90, 90, 90, 70, 70]

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
    ]))    
    uptime_percentage = round((100-avg_downtime), 4)
    # Table Header        
    datainfo = [["Report Time Span:", f"{fromdate} - {todate}"]]
    datainfo.append(["Sensor Type:", f"SNMP Traffic ({snmp_interval} interval)"]) 

    success_polls = total_polls - total_ping_loss
    good_stats = round( ( ( success_polls / total_polls ) * 100), 4)
    failed_stats = round( ( (total_ping_loss / total_polls) * 100), 4) 
    # Create the bar
    uptime_bar = UptimeBar(uptime_percentage, width=8, height=25)  # small horizontal bar
    # Combine text and bar in a mini table (like an HBox)
    mini_table = Table([[f"UP:{uptime_percentage}%", uptime_bar, f"[{uptime_str}]", f"Down: {avg_downtime}%" ]])
    mini_table.setStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")])    
    #datainfo.append(["Uptime stats:", f"UP:{uptime_percentage}%", uptime_bar, f"[{uptime_str}]  Down: {avg_downtime}%"]) 
    datainfo.append(["Uptime stats:", mini_table])

    reqtime_bar = UptimeBar(good_stats, width=8, height=25) 
    # Combine text and bar in a mini table (like an HBox)
    mini_table1 = Table([[f"Good:{good_stats}%", reqtime_bar, f"[{success_polls}]", f"Failed:{failed_stats}% [{total_ping_loss}]" ]])
    mini_table1.setStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")])
    datainfo.append(["Request Stats:", mini_table1])

    #datainfo.append(["Request Stats:", f"Good:{good_stats}%", reqtime_bar, f"[{success_polls}]", f"Failed:{failed_stats}% [{total_ping_loss}]"])
    datainfo.append(["Average(Traffic Total):", f"{str(avg_speed)} Mbit/s"])
    datainfo.append(["Total(Traffic Total):", f"{str(total_traffic)} MB"])
    datainfo.append(["Percentile:", f"{str(percentile)} Mbit/s"])
    tableinfo = Table(datainfo, rowHeights=25)    
    columninfo_widths = [150, 300]
    tableinfo = Table(datainfo, colWidths=columninfo_widths, rowHeights=35)    
    # Add table styles
    tableinfo.setStyle(TableStyle([       
 
        ('FONTSIZE', (0, 0), (-1, -1), 12),  # Adjust font size for better fit
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
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
    tableinfo.hAlign = 'LEFT'  # Ensure image is aligned to the left
    elements.append(tableinfo)
    elements.append(Spacer(1, 12))  # More space before the image      
    try:
        graphimg = Image(graphname, width=500, height=200)  # Adjust size as needed
        graphimg.hAlign = 'LEFT'  # Ensure image is aligned to the left
        elements.append(Spacer(1, 12))  # Ensure spacing before adding the image
        elements.append(graphimg)
        elements.append(Spacer(1, 20))  # Space below the image
    except:
        print("Graph not found, continuing without it.")
    elements.append(tableconsolidated)
    elements.append(Spacer(1, 12))  # More space before the table
    elements.append(table)
    # Build PDF
    doc.build(elements)
    print(f"Traffic data saved to {filename}")

def traffic_report_gen(data):
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
        item_ids, interface_sampesperhr, snmp_interval = get_item_id(hostid, intfcname)        
        if not item_ids:
            print("No relevant items found.")            
            response = [{"message": "No relevant items found.", "status": False}]            
            return response
        for name, itemid in item_ids.items():
            if "received" in name:
                itemidreceived = itemid                
            if "sent" in name:
                itemidsent = itemid         
        itemidping, icmp_samplesperhr = get_item_id_ping(hostid)
        graphname = intfcname.split("Interface ")[1]     
        graphid = get_graph_id(hostid, graphname)          
        if not graphid:
            graphid = graph_create(itemidsent, itemidreceived, itemidping, graphname)
        if graphid: 
            download_graph_name = download_graph(graphid, fromdate, todate)
            if(download_graph_name):
                    uptime_str = get_item_id_uptime(hostid)                    
                    save_to_pdf(intfcname, branch_location, fromdate, todate, download_graph_name, itemidreceived, itemidsent, uptime_str, interval, itemidping, interface_sampesperhr, icmp_samplesperhr, snmp_interval, data['filename']) 
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