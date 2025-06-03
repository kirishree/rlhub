from rest_framework import serializers

class authloginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

class AuthLoginResponseSerializer(serializers.Serializer):
    access = serializers.CharField()
    refresh = serializers.CharField()
    message = serializers.CharField()
    msg_status = serializers.CharField()

class activateinfoSerializer(serializers.Serializer):
    tunnel_ip = serializers.CharField()
    uuid = serializers.CharField()
    hub_ip = serializers.CharField()

class MessageSerializer(serializers.Serializer):
    message = serializers.CharField()

class hubinfoSerializer(serializers.Serializer):
    hub_wan_ip = serializers.CharField()
    uuid = serializers.CharField()    

class deviceinfoSerializer(serializers.Serializer):
    tunnel_ip = serializers.CharField()
    uuid = serializers.CharField()    

class RouteEntrySerializer(serializers.Serializer):
    protocol = serializers.CharField()
    destination = serializers.CharField()
    gateway = serializers.CharField()
    metric = serializers.CharField()
    outgoint_interface_name = serializers.CharField()
    table_id = serializers.CharField()

class InterfaceEntrySerializer(serializers.Serializer):
    interface_name = serializers.CharField()
    mac_address = serializers.CharField()
    type = serializers.CharField()
    mtu = serializers.CharField()
    addresses = serializers.CharField()
    status = serializers.CharField()