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

# Zabbix API URL
zabbix_api_url = "http://185.69.209.251/zabbix/api_jsonrpc.php" # Replace with your Zabbix API URL
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
        intfcname = name.split(" ")[1].split(":")[0]
        print("intfcname", intfcname)
        response = session.post(zabbix_api_url, json=get_item)
        result = response.json().get('result', [])
        items = {item["name"]: item["itemid"] for item in result if "Bits" in item["name"] and intfcname in item["name"]}
        return items
    except Exception as e:
        print(f"Failed to get item list: {e}")
        return {}

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

def get_trends(itemid):    
    get_trend = {
        "jsonrpc": "2.0",
        "method": "trend.get",
        "params": {
            "output": "extend",
            "itemids": itemid            
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
    
def save_to_text(data, filename="traffic_data.txt"):
    """Save the traffic data to a text file."""
    with open(filename, "w") as file:
        for timestamp, value in data:
            file.write(f"{timestamp}: {value} bits\n")
    print(f"Traffic data saved to {filename}")

def convert_to_mb(bits):
    """Convert bits to Megabytes (MB)."""
    #return round(int(bits) / (8 * 1024 * 1024), 4)
    return round(int(bits) / (1024 * 1024), 4)

def convert_to_mbps(bits):
    """Convert bits to Megabits per second (Mbit/s)."""
    return round(int(bits) / (1024 * 1024), 4)

def save_to_pdf(datain, dataout, intfcname, filename="traffic_data.pdf", logo_path="logo.png"):
    """Generate a well-structured PDF report with logo, traffic data, and percentile details."""

    # Define PDF document with margins
    doc = SimpleDocTemplate(filename, pagesize=letter,
                            leftMargin=30, rightMargin=30, topMargin=40, bottomMargin=40)
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
    title = Paragraph(f"<b>Network Traffic Report for {intfcname}</b>", styles["Title"])
    subtitle = Paragraph(f"<b>Generated on:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"])
    
    elements.append(title)
    elements.append(Spacer(1, 12))  # Space
    elements.append(subtitle)
    elements.append(Spacer(1, 20))  # More space before the table

    # Table Header
    data = [["Date & Time", "In Min (MB)", "In Max (MB)", "In Avg (MB)", 
             "Out Min (MB)", "Out Max (MB)", "Out Avg (MB)", "Total Speed (Mbit/s)"]]

    in_avg_values = []
    out_avg_values = []
    total_speed_values = []

    # Add data rows
    for i in range(len(datain)):
        time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(datain[i]["clock"])))
        in_min = convert_to_mb(datain[i]["value_min"])
        in_max = convert_to_mb(datain[i]["value_max"])
        in_avg = convert_to_mb(datain[i]["value_avg"])
        out_min = convert_to_mb(dataout[i]["value_min"])
        out_max = convert_to_mb(dataout[i]["value_max"])
        out_avg = convert_to_mb(dataout[i]["value_avg"])
        total_speed = convert_to_mbps(int(datain[i]["value_avg"]) + int(dataout[i]["value_avg"]))

        # Store values for percentile calculation
        in_avg_values.append(int(datain[i]["value_avg"]))
        out_avg_values.append(int(dataout[i]["value_avg"]))
        total_speed_values.append(int(datain[i]["value_avg"]) + int(dataout[i]["value_avg"]))

        row = [time_str, in_min, in_max, in_avg, out_min, out_max, out_avg, total_speed]
        data.append(row)

    # Calculate 95th percentile
    in_95th = convert_to_mbps(np.percentile(in_avg_values, 95))
    out_95th = convert_to_mbps(np.percentile(out_avg_values, 95))
    total_95th = convert_to_mbps(np.percentile(total_speed_values, 95))

    # Append 95th percentile row to table
    data.append(["95th Percentile", "-", "-", in_95th, "-", "-", out_95th, total_95th])

    # Set column widths to fit within the page
    column_widths = [110, 70, 70, 70, 70, 70, 70, 90]

    # Create the table with defined column widths
    table = Table(data, colWidths=column_widths)

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
        ('BACKGROUND', (0, -1), (-1, -1), colors.lightgrey),  # 95th percentile row highlight
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
    ]))

    elements.append(table)

    # Build PDF
    doc.build(elements)

    print(f"Traffic data saved to {filename}")

def save_to_pdf2(datain, dataout, filename="traffic_data.pdf"):
    """Generate a properly formatted PDF report with headings and traffic data."""

    # Define PDF document with margins
    doc = SimpleDocTemplate(filename, pagesize=letter,
                            leftMargin=30, rightMargin=30, topMargin=40, bottomMargin=40)
    elements = []

    # Get styles for headings
    styles = getSampleStyleSheet()
    
    # **Title & Subtitle**
    title = Paragraph("<b>Network Traffic Report for Interface Gi0/0/1</b>", styles["Title"])
    subtitle = Paragraph(f"<b>Generated on:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"])
    
    elements.append(title)
    elements.append(Spacer(1, 12))  # Add space
    elements.append(subtitle)
    elements.append(Spacer(1, 20))  # More space before the table

    # Table Header
    data = [["Date & Time", "In Min", "In Max", "In Avg", "Out Min", "Out Max", "Out Avg"]]

    # Add data rows
    for i in range(len(datain)):
        time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(datain[i]["clock"])))
        row = [
            time_str,
            str(datain[i]["value_min"]), str(datain[i]["value_max"]), str(datain[i]["value_avg"]),
            str(dataout[i]["value_min"]), str(dataout[i]["value_max"]), str(dataout[i]["value_avg"])
        ]
        data.append(row)

    # Set column widths to fit within the page
    column_widths = [110, 70, 70, 70, 70, 70, 70]

    # Create the table with defined column widths
    table = Table(data, colWidths=column_widths)

    # Add table styles
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),  # Header background color
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  # Header text color
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),  # Adjust font size for better fit
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),  # Grid for table
    ]))

    elements.append(table)

    # Build PDF
    doc.build(elements)

    print(f"Traffic data saved to {filename}")


def save_to_pdf1(datain, dataout, filename="traffic_data.pdf"):
    """Generate a PDF report with traffic data in a structured table format."""
    
    # Define the PDF document
    doc = SimpleDocTemplate(filename, pagesize=letter)
    elements = []
    
    # Table Header
    data = [["Date & Time", "Incoming Min (bits)", "Incoming Max (bits)", "Incoming Avg (bits)",
             "Outgoing Min (bits)", "Outgoing Max (bits)", "Outgoing Avg (bits)"]]
    
    # Add data rows
    for i in range(len(datain)):
        time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(datain[i]["clock"])))
        row = [
            time_str,
            datain[i]["value_min"], datain[i]["value_max"], datain[i]["value_avg"],
            dataout[i]["value_min"], dataout[i]["value_max"], dataout[i]["value_avg"]
        ]
        data.append(row)
    
    # Create the table
    table = Table(data)
    
    # Add table styles
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),  # Header background color
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  # Header text color
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),  # Grid for table
    ]))
    
    elements.append(table)
    
    # Build PDF
    doc.build(elements)
    
    print(f"Traffic data saved to {filename}")


def main():
    try:
        #hostid = get_host_id("DUBAI-UAE")
        hostid = "10084"
        intfcname = "Interface enp0s3: Network traffic"
        if not hostid:
            print("Host ID not found.")
            return

        item_ids = get_item_id(hostid, intfcname)
        print(item_ids)
        if not item_ids:
            print("No relevant items found.")
            return

        all_data = []
        for name, itemid in item_ids.items():
            #history = get_history(itemid)
            trend = get_trends(itemid)
            if "received" in name:
                incoming_traffic = trend                
            if "sent" in name:
                outgoing_traffic = trend            
        

        if incoming_traffic:
            #save_to_text(all_data)
            save_to_pdf(incoming_traffic, outgoing_traffic, intfcname)
        else:
            print("No history data retrieved.")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
