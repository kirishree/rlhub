def add_rate_limitold(data):   
   # Define the router details
    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]

    # Create an SSH client instance
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        try:
            # Connect to the router
            ssh_client.connect(hostname=router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        except Exception as e:
            logger.error(
            f"SSH Connection error",
            extra={
                "device_type": "Microtek",
                "device_ip": router_ip,
                "be_api_endpoint": "add_ratelimit",
                "exception": str(e)
            }
            )
            return [{"message": "Error - SSH Connection error"}]
        try:
            branch_id = data["tunnel_ip"].split("/")[0]
            cache_key = f"interfaces_branch_{branch_id}"
            interface_details = cache.get(cache_key)
            if not interface_details:
                interface_details, respp = interfacedetails(data)
            for intfc in interface_details:
                if intfc["interface_name"] == "bridge":
                    lan_ip = intfc["addresses"]
            
            for limit in data["rules"]:
                # Execute the trace command 
                lan_ntwk = False
                for lanaddr in lan_ip:
                    if is_in_same_network(limit["target_address"].split("/")[0], lanaddr["IPv4address"]):
                        lan_ntwk = True
                        break
                if lan_ntwk:
                    max_limit = f'{limit["max_upload_limit"]}M/{limit["max_download_limit"]}M'
                    
                    queue_name = f"quota_{limit['target_address'].split("/")[0]}"
                    
                    stdin, stdout, stderr = ssh_client.exec_command(f'/queue simple add name={queue_name} comment={limit["description"]} target={limit["target_address"]} max-limit={max_limit}')
                    is_output =  stdout.read().decode()
                    is_error =  stderr.read().decode()
                    if is_error:
                        break
                    else:
                        quota_limit = int(limit.get("volume_limit")) * 1000000000
                        check_script_name = f"check_quota_{limit['target_address'].split("/")[0]}"
                        check_script_cmd = f"""/system script add name={check_script_name} policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive source="
:local limit {quota_limit}; # 1GB in bytes
:local qname "{queue_name}"

:local usage [/queue simple get [find name=$qname] bytes]

# Split into upload and download
:local tx [:pick $usage 0 [:find $usage "/"]]
:local rx [:pick $usage ([:find $usage "/"] + 1) [:len $usage]]

:local total ( $tx + $rx )

:log info ("Current usage for " . $qname . ": TX=" . $tx . " bytes, RX=" . $rx . " bytes, TOTAL=" . $total . " bytes")

:if ($total > $limit) do={
    /queue simple set [find name=$qname] max-limit=64k/64k
    :log warning ("Client quota exceeded for " . $qname . " - blocked")
}
"
"""
                    stdin, stdout, stderr = ssh_client.exec_command(check_script_cmd)
                    #Script to reset at Midnight                    
                    reset_script_name = f"reset_quota_{limit['target_address'].split("/")[0]}" 
                    reset_script_cmd = f"""/system script add name={reset_script_name} source="
:local qname "{queue_name}"
/queue simple reset-counters [find name=$qname]
/queue simple set [find name=$qname] max-limit={max_limit}
:log info ("Daily quota reset for " . $qname)
"
""""
                    
                    stdin, stdout, stderr = ssh_client.exec_command(reset_script_cmd)
                    #Check Scheduler run for every 5 min
                    check_sched_name = f"check_sched_{limit['target_address'].split("/")[0]}" 
                    check_sched_cmd = f"/system scheduler add name={check_sched_name} interval=5m on-event={check_script_name}"
                    stdin, stdout, stderr = ssh_client.exec_command(check_sched_cmd)
                    #Reset Scheduler
                    reset_sched_name = f"reset_sched_{limit['target_address'].split("/")[0]}"
                    reset_sched_cmd = f"/system scheduler add name={reset_sched_name} start-time=00:00:00 interval=1d on-event={reset_script_name}"
                    stdin, stdout, stderr = ssh_client.exec_command(check_sched_cmd)
                    response = [{"message": "Rate limit applied successfully"}]
                else:
                    response = [{"message": "Error: Target Address should be in LAN Network"}]
                    break
        except Exception as e:
            logger.error(
                f"Error while applying ratelimit",
                extra={
                    "device_type": "Microtek",
                    "device_ip": router_ip,
                    "be_api_endpoint": "add_ratelimit",
                    "exception": str(e)
                }
            )
            response = [{"message": "Error - Internal Server Error"}]         
        # Close the SSH connection
        ssh_client.close()         
    except Exception as e:
        response = [{"message": "Error - Internal Server Error"}]
        logger.error(
                f"{str(e)}",
                extra={
                    "device_type": "Microtek",
                    "device_ip": router_ip,
                    "be_api_endpoint": "add_ratelimit",
                    "exception": str(e)
                }
            )
    return response           
def add_rate_limit(data):   
    import paramiko
    import logging
    import ipaddress

    logger = logging.getLogger(__name__)

    router_ip = data["tunnel_ip"].split("/")[0]
    username = data["router_username"]
    password = data["router_password"]

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        try:
            # Connect to the router
            ssh_client.connect(
                hostname=router_ip,
                username=username,
                password=password,
                look_for_keys=False,
                allow_agent=False
            )
        except Exception as e:
            logger.error(
                "SSH Connection error",
                extra={
                    "device_type": "MikroTik",
                    "device_ip": router_ip,
                    "be_api_endpoint": "add_ratelimit",
                    "exception": str(e)
                }
            )
            return [{"message": "Error - SSH Connection error"}]

        try:
            branch_id = data["tunnel_ip"].split("/")[0]
            cache_key = f"interfaces_branch_{branch_id}"
            interface_details = cache.get(cache_key)
            if not interface_details:
                interface_details, _ = interfacedetails(data)

            lan_ip = []
            for intfc in interface_details:
                if intfc["interface_name"] == "bridge":
                    lan_ip = intfc["addresses"]

            for limit in data["rules"]:
                # Check if address belongs to LAN network
                lan_ntwk = False
                for lanaddr in lan_ip:
                    if is_in_same_network(limit["target_address"].split("/")[0], lanaddr["IPv4address"]):
                        lan_ntwk = True
                        break

                if lan_ntwk:
                    max_limit = f'{limit["max_upload_limit"]}M/{limit["max_download_limit"]}M'
                    target_ip = limit['target_address'].split('/')[0]

                    queue_name = f"quota_{target_ip}"

                    # Add queue
                    stdin, stdout, stderr = ssh_client.exec_command(
                        f'/queue simple add name={queue_name} comment="{limit["description"]}" target={limit["target_address"]} max-limit={max_limit}'
                    )
                    is_error = stderr.read().decode().strip()

                    if is_error:
                        logger.warning(f"Queue add error: {is_error}")
                        continue

                    quota_limit = int(limit.get("volume_limit", 0)) * 1000000000  # in bytes

                    check_script_name = f"check_quota_{target_ip}"
                    check_script_cmd = f"""/system script add name={check_script_name} source="
:local limit {quota_limit}
:local qname "{queue_name}"

:local usage [/queue simple get [find name=$qname] bytes]

:local tx [:pick $usage 0 [:find $usage "/"]]
:local rx [:pick $usage ([:find $usage "/"] + 1) [:len $usage]]

:local total ($tx + $rx)

:log info ("Current usage for " . $qname . ": TX=" . $tx . " bytes, RX=" . $rx . " bytes, TOTAL=" . $total . " bytes")

:if ($total > $limit) do={{
    /queue simple set [find name=$qname] max-limit=64k/64k
    :log warning ("Client quota exceeded for " . $qname . " - blocked")
}}
"
"""
                    ssh_client.exec_command(check_script_cmd)

                    # Reset script (daily reset at midnight)
                    reset_script_name = f"reset_quota_{target_ip}"
                    reset_script_cmd = f"""/system script add name={reset_script_name} source="
:local qname "{queue_name}"
/queue simple reset-counters [find name=$qname]
/queue simple set [find name=$qname] max-limit={max_limit}
:log info ("Daily quota reset for " . $qname)
"
"""
                    ssh_client.exec_command(reset_script_cmd)

                    # Scheduler for check every 5 min
                    check_sched_name = f"check_sched_{target_ip}"
                    check_sched_cmd = f"/system scheduler add name={check_sched_name} interval=5m on-event={check_script_name}"
                    ssh_client.exec_command(check_sched_cmd)

                    # Scheduler for reset at midnight
                    reset_sched_name = f"reset_sched_{target_ip}"
                    reset_sched_cmd = f"/system scheduler add name={reset_sched_name} start-time=00:00:00 interval=1d on-event={reset_script_name}"
                    ssh_client.exec_command(reset_sched_cmd)

                    response = [{"message": "Rate limit applied successfully"}]
                else:
                    response = [{"message": "Error: Target Address should be in LAN Network"}]
                    break

        except Exception as e:
            logger.error(
                "Error while applying ratelimit",
                extra={
                    "device_type": "MikroTik",
                    "device_ip": router_ip,
                    "be_api_endpoint": "add_ratelimit",
                    "exception": str(e)
                }
            )
            response = [{"message": "Error - Internal Server Error"}]

        ssh_client.close()

    except Exception as e:
        response = [{"message": "Error - Internal Server Error"}]
        logger.error(
            str(e),
            extra={
                "device_type": "MikroTik",
                "device_ip": router_ip,
                "be_api_endpoint": "add_ratelimit",
                "exception": str(e)
            }
        )
    return response
    check_script_name = "check_quota_192.168.88.23"
    quota_limit = 1000000000
    queue_name = "quota_192.168.88.23"
    check_script_cmd = f"""/system script add name={check_script_name} policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive source=":local limit {quota_limit}; :local qname \\"{queue_name}\\"; :local usage [/queue simple get [find name=$qname] bytes]; :local tx [:pick $usage 0 [:find $usage "/"]]; :local rx [:pick $usage ([:find $usage "/"] + 1) [:len $usage]]; :local total ($tx + $rx); :log info (\\"Current usage for \\" . $qname . \\": TOTAL=\\" . $total . \\" bytes\\"); :if ($total > $limit) do={{ /queue simple set [find name=$qname] max-limit=64k/64k; :log warning (\\"Client quota exceeded for \\" . $qname . \\" - blocked\\"); }}" """


#check_script_cmd = f"""/system script add name={check_script_name} source=":local limit {quota_limit} :local qname "{queue_name}" :local usage [/queue simple get [find name=$qname] bytes] :local tx [:pick $usage 0 [:find $usage "/"]] :local rx [:pick $usage ([:find $usage "/"] + 1) [:len $usage]] :local total ($tx + $rx) :log info ("Current usage for " . $qname . ": TX=" . $tx . " bytes, RX=" . $rx . " bytes, TOTAL=" . $total . " bytes") :if ($total > $limit) do={{ /queue simple set [find name=$qname] max-limit=64k/64k :log warning ("Client quota exceeded for " . $qname . " - blocked")}}" """
                    #check_script_cmd = f"""/system script add name={check_script_name} policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive source=":local limit {quota_limit}; :local qname \\"{queue_name}\\"; :local usage [/queue simple get [find name=$qname] bytes]; :local tx [:pick $usage 0 [:find $usage "/"]]; :local rx [:pick $usage ([:find $usage "/"] + 1) [:len $usage]]; :local total ($tx + $rx); :log info (\\"Current usage for \\" . $qname . \\": TOTAL=\\" . $total . \\" bytes\\"); :if ($total > $limit) do={{ /queue simple set [find name=$qname] max-limit=64k/64k; :log warning (\\"Client quota exceeded for \\" . $qname . \\" - blocked\\"); }}" """