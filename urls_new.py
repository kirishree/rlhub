""" URL configuration for reachlink project.

The `urlpatterns` list routes URLs to views. For more information please see: 
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples: Function views 1. Add an import: from my_app import views 2. Add a URL to 
    urlpatterns: path('', views.home, name='home')
Class-based views 1. Add an import: from other_app.views import Home 2. Add a URL to 
    urlpatterns: path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.urls import path
from reach.views import login, onboard_block, onboard_unblock, ping_spoke, autofix
from reach.views import branch_info, get_routing_table, addsubnet, diagnostics
from reach.views import activate, deactivate, delsubnet, onboard_delete
from reach.views import spoke_update, add_cisco_device
from reach.views import lan_info, lan_config, dhcp_config, traceroute_hub, traceroute_spoke, add_ip_rule_spoke, get_routing_table_spoke, get_interface_details_spoke, create_vlan_interface_spoke, interface_config_spoke
from reach.views import vlan_interface_delete_spoke, add_route_spoke, get_pbr_info_spoke, addstaticroute_hub, delstaticroute_hub, del_staticroute_spoke, get_interface_details_hub, add_cisco_hub
from reach.views import get_configured_hub, hub_info, get_ciscospoke_config, get_ciscohub_config
from reach.views import create_vlan_interface_hub, create_sub_interface_hub, create_loopback_interface_hub, interface_config_hub
from reach.views import vlan_interface_delete_hub, create_tunnel_interface_hub, create_loopback_interface_spoke, create_sub_interface_spoke, create_tunnel_interface_spoke
from reach.views import login_or_register, change_password, homepage_info, get_microtekspoke_config, traffic_report
urlpatterns = [
    path('token', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('homepage_info', homepage_info, name='homepage_info'),
    path('auth', login_or_register, name='login_or_register'),
    path('auth/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('add_ip_rule_spoke', add_ip_rule_spoke, name='add_ip_rule_spoke'),
    path('traceroute_hub', traceroute_hub, name='traceroute_hub'),
    path('traceroute_spoke', traceroute_spoke, name='traceroute_spoke'),
    path('add_cisco_device', add_cisco_device, name='add_cisco_device'),
    path('onboard_delete', onboard_delete, name='onboard_delete'),
    path('spoke_update', spoke_update, name='spoke_update'),
    path('branch_info', branch_info, name='branch_info'),
    path('onboard_block', onboard_block, name='onboard_block'),
    path('onboard_unblock', onboard_unblock, name='onboard_unblock'),
    path('get_routing_table', get_routing_table, name='get_routing_table'),
    path('addsubnet', addsubnet, name='addsubnet'),
    path('delsubnet', delsubnet, name='delsubnet'),
    path('login', login, name='login'),
    path('ping_spoke', ping_spoke, name='ping_spoke'),
    path('autofix', autofix, name='autofix'),
    path('diagnostics', diagnostics, name='diagnostics'),
    path('deactivate', deactivate, name='deactivate'),
    path('activate', activate, name='activate'),
    path('lan_info', lan_info, name='lan_info'),
    path('lan_config', lan_config, name='lan_config'),
    path('dhcp_config', dhcp_config, name='dhcp_config'),
    path('get_routing_table_spoke', get_routing_table_spoke, name='get_routing_table_spoke'),
    path('get_interface_details_spoke', get_interface_details_spoke, name='get_interface_details_spoke'),
    path('create_vlan_interface_spoke', create_vlan_interface_spoke, name='create_vlan_interface_spoke'),
    path('interface_config_spoke', interface_config_spoke, name='interface_config_spoke'),
    path('vlan_interface_delete_spoke', vlan_interface_delete_spoke, name='vlan_interface_delete_spoke'),
    path('add_route_spoke', add_route_spoke, name='add_route_spoke'),
    path('get_pbr_info_spoke', get_pbr_info_spoke, name='get_pbr_info_spoke'),
    path('addstaticroute_hub', addstaticroute_hub, name='addstaticroute_hub'),
    path('deletestaticroute_hub', delstaticroute_hub, name='delstaticroute_hub'),
    path('del_staticroute_spoke', del_staticroute_spoke, name='del_staticroute_spoke'),
    path('get_interface_details_hub', get_interface_details_hub, name='get_interface_details_hub'),
    path('add_cisco_hub', add_cisco_hub, name='add_cisco_hub'),
    path('get_configured_hub', get_configured_hub, name='get_configured_hub'),
    path('hub_info', hub_info, name='hub_info'),
    path('get_ciscospoke_config', get_ciscospoke_config, name='get_ciscospoke_config'),
    path('get_ciscohub_config', get_ciscohub_config, name='get_ciscohub_config'),
    path('create_vlan_interface_hub', create_vlan_interface_hub, name='create_vlan_interface_hub'),
    path('create_sub_interface_hub', create_sub_interface_hub, name='create_sub_interface_hub'),
    path('create_loopback_interface_hub', create_loopback_interface_hub, name='create_loopback_interface_hub'),
    path('vlan_interface_delete_hub', vlan_interface_delete_hub, name='vlan_interface_delete_hub'),
    path('create_tunnel_interface_hub', create_tunnel_interface_hub, name='create_tunnel_interface_hub'),
    path('create_loopback_interface_spoke', create_loopback_interface_spoke, name='create_loopback_interface_spoke'),
    path('create_sub_interface_spoke', create_sub_interface_spoke, name='create_sub_interface_spoke'),
    path('create_tunnel_interface_spoke', create_tunnel_interface_spoke, name='create_tunnel_interface_spoke'),
    path('interface_config_hub', interface_config_hub, name='interface_config_hub'),
    path('change_password', change_password, name='change_password'),
    path('get_microtekspoke_config', get_microtekspoke_config, name='get_microtekspoke_config'),
    path('traffic_report',traffic_report, name='traffic_report'),
]
