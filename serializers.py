from rest_framework import serializers

class AuthLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

class AuthLoginResponseSerializer(serializers.Serializer):
    access = serializers.CharField()
    refresh = serializers.CharField()
    message = serializers.CharField()
    msg_status = serializers.CharField()

class ActivateInfoSerializer(serializers.Serializer):
    tunnel_ip = serializers.CharField()
    uuid = serializers.CharField()
    hub_ip = serializers.CharField()

class MessageSerializer(serializers.Serializer):
    message = serializers.CharField()

class HubInfoSerializer(serializers.Serializer):
    hub_wan_ip = serializers.CharField()
    uuid = serializers.CharField()    

class DeviceInfoSerializer(serializers.Serializer):
    tunnel_ip = serializers.CharField()
    uuid = serializers.CharField()    

class RouteEntrySerializer(serializers.Serializer):
    protocol = serializers.CharField()
    destination = serializers.CharField()
    gateway = serializers.CharField()
    metric = serializers.CharField()
    outgoint_interface_name = serializers.CharField()
    table_id = serializers.CharField()

class SubnetInfoSerializer(serializers.Serializer):
    subnet = serializers.CharField()
    gateway = serializers.CharField()

class AddRouteInfoSerializer(serializers.Serializer):
    tunnel_ip = serializers.CharField()
    uuid = serializers.CharField() 
    subnet_info = serializers.ListField(
        child=SubnetInfoSerializer()
    )

class RoutesInfoSerializer(serializers.Serializer):
    destination = serializers.CharField()
    gateway = serializers.CharField()

class DelRouteInfoSerializer(serializers.Serializer):
    tunnel_ip = serializers.CharField()
    uuid = serializers.CharField() 
    routes_info = serializers.ListField(
        child=RoutesInfoSerializer()
    )

class InterfaceEntrySerializer(serializers.Serializer):
    interface_name = serializers.CharField()
    mac_address = serializers.CharField()
    type = serializers.CharField()
    mtu = serializers.CharField()
    addresses = serializers.CharField()
    status = serializers.CharField()

class PingHubInfoSerializer(serializers.Serializer):
    hub_wan_ip = serializers.CharField()
    uuid = serializers.CharField() 
    subnet = serializers.CharField() 

class PingSpokeInfoSerializer(serializers.Serializer):
    tunnel_ip = serializers.CharField()
    uuid = serializers.CharField() 
    subnet = serializers.CharField() 
    
class TraceSpokeInfoSerializer(serializers.Serializer):
    tunnel_ip = serializers.CharField()
    uuid = serializers.CharField() 
    trace_ip = serializers.CharField() 
    
class TraceHubInfoSerializer(serializers.Serializer):
    hub_wan_ip = serializers.CharField()
    uuid = serializers.CharField() 
    trace_ip = serializers.CharField()

class DestinationInfoSerializer(serializers.Serializer):
    destination = serializers.CharField()
    gateway = serializers.CharField()

class RouteHubSerializer(serializers.Serializer):
    hub_wan_ip = serializers.CharField()
    uuid = serializers.CharField() 
    routes_info = serializers.ListField(
        child=DestinationInfoSerializer()
    )

class VlanAddHubSerializer(serializers.Serializer):
    hub_wan_ip = serializers.CharField()
    uuid = serializers.CharField() 
    vlan_id = serializers.CharField() 
    link = serializers.ListField()
    addresses = serializers.ListField()

class LoopbackAddHubSerializer(serializers.Serializer):
    hub_wan_ip = serializers.CharField()
    uuid = serializers.CharField() 
    loopback_intfc_name = serializers.CharField()     
    addresses = serializers.ListField()

class TunnelAddHubSerializer(serializers.Serializer):
    hub_wan_ip = serializers.CharField()
    uuid = serializers.CharField() 
    tunnel_intfc_name = serializers.CharField()    
    link = serializers.ListField() 
    destination_ip = serializers.CharField() 
    addresses = serializers.ListField()

class DeleteInterfaceHubSerializer(serializers.Serializer):
    hub_ip = serializers.CharField()
    uuid = serializers.CharField() 
    intfc_name = serializers.CharField()     

class ConfigInterfaceHubSerializer(serializers.Serializer):
    hub_wan_ip = serializers.CharField()
    uuid = serializers.CharField() 
    intfc_name = serializers.CharField()     
    addresses = serializers.ListField()
    
class VlanAddSpokeSerializer(serializers.Serializer):
    tunnel_ip = serializers.CharField()
    uuid = serializers.CharField() 
    vlan_id = serializers.CharField() 
    link = serializers.ListField()
    addresses = serializers.ListField()

class LoopbackAddSpokeSerializer(serializers.Serializer):
    tunnel_ip = serializers.CharField()
    uuid = serializers.CharField() 
    loopback_intfc_name = serializers.CharField()     
    addresses = serializers.ListField()

class TunnelAddSpokeSerializer(serializers.Serializer):
    tunnel_ip = serializers.CharField()
    uuid = serializers.CharField() 
    tunnel_intfc_name = serializers.CharField()    
    link = serializers.ListField() 
    destination_ip = serializers.CharField() 
    addresses = serializers.ListField()

class ConfigInterfaceSpokeSerializer(serializers.Serializer):
    tunnel_ip = serializers.CharField()
    uuid = serializers.CharField() 
    intfc_name = serializers.CharField()     
    addresses = serializers.ListField()

class DeleteInterfaceSpokeSerializer(serializers.Serializer):
    tunnel_ip = serializers.CharField()
    uuid = serializers.CharField() 
    intfc_name = serializers.CharField()     