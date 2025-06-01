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
from django.contrib.auth import views as auth_views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.urls import path
from django.urls import path, re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from reach.views import login, onboard_block, onboard_unblock, ping_spoke, autofix
from reach.views import branch_info, get_routing_table, addsubnet, diagnostics
from reach.views import activate, deactivate, delsubnet, onboard_delete
from reach.views import spoke_update, add_cisco_device
from reach.views import lan_info, lan_config, dhcp_config, traceroute_hub, traceroute_spoke, add_ip_rule_spoke, get_routing_table_spoke, get_interface_details_spoke, create_vlan_interface_spoke, interface_config_spoke
from reach.views import vlan_interface_delete_spoke, add_route_spoke, get_pbr_info_spoke, addstaticroute_hub, delstaticroute_hub, del_staticroute_spoke, get_interface_details_hub, add_cisco_hub
from reach.views import get_configured_hub, hub_info, get_ciscospoke_config, get_ciscohub_config
from reach.views import create_vlan_interface_hub, create_sub_interface_hub, create_loopback_interface_hub, interface_config_hub
from reach.views import vlan_interface_delete_hub, create_tunnel_interface_hub, create_loopback_interface_spoke, create_sub_interface_spoke, create_tunnel_interface_spoke
from reach.views import login_or_register, change_password, homepage_info, get_microtekspoke_config, traffic_report, get_robustelspoke_config, adminhomepage_info, logfile_content
schema_view = get_schema_view(
   openapi.Info(
      title="ReachLink",
      default_version='v1',
      description="API documentation for ReachLink project",
      terms_of_service="https://www.yourcompany.com/terms/",
      contact=openapi.Contact(email="bavya@cloudetel.com"),
      license=openapi.License(name="BSD License"),
   ),
    public=True,
   permission_classes=(permissions.AllowAny,),
)

urlpatterns = [   
    path('beapi/accounts/login/', auth_views.LoginView.as_view(), name='login'),
    path('beapi/token', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('beapi/homepage_info', homepage_info, name='homepage_info'),
    path('beapi/adminhomepage_info', adminhomepage_info, name='adminhomepage_info'),
    path('beapi/auth', login_or_register, name='login_or_register'),
    path('beapi/auth/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('beapi/add_ip_rule_spoke', add_ip_rule_spoke, name='add_ip_rule_spoke'),
    path('beapi/traceroute_hub', traceroute_hub, name='traceroute_hub'),
    path('beapi/traceroute_spoke', traceroute_spoke, name='traceroute_spoke'),
    path('beapi/add_cisco_device', add_cisco_device, name='add_cisco_device'),
    path('beapi/onboard_delete', onboard_delete, name='onboard_delete'),
    path('beapi/spoke_update', spoke_update, name='spoke_update'),
    path('beapi/branch_info', branch_info, name='branch_info'),
    path('beapi/onboard_block', onboard_block, name='onboard_block'),
    path('beapi/onboard_unblock', onboard_unblock, name='onboard_unblock'),
    path('beapi/get_routing_table', get_routing_table, name='get_routing_table'),
    path('beapi/addsubnet', addsubnet, name='addsubnet'),
    path('beapi/delsubnet', delsubnet, name='delsubnet'),
    path('beapi/login', login, name='login'),
    path('beapi/ping_spoke', ping_spoke, name='ping_spoke'),
    path('beapi/autofix', autofix, name='autofix'),
    path('beapi/diagnostics', diagnostics, name='diagnostics'),
    path('beapi/deactivate', deactivate, name='deactivate'),
    path('beapi/activate', activate, name='activate'),
    path('beapi/lan_info', lan_info, name='lan_info'),
    path('beapi/lan_config', lan_config, name='lan_config'),
    path('beapi/dhcp_config', dhcp_config, name='dhcp_config'),
    path('beapi/get_routing_table_spoke', get_routing_table_spoke, name='get_routing_table_spoke'),
    path('beapi/get_interface_details_spoke', get_interface_details_spoke, name='get_interface_details_spoke'),
    path('beapi/create_vlan_interface_spoke', create_vlan_interface_spoke, name='create_vlan_interface_spoke'),
    path('beapi/interface_config_spoke', interface_config_spoke, name='interface_config_spoke'),
    path('beapi/vlan_interface_delete_spoke', vlan_interface_delete_spoke, name='vlan_interface_delete_spoke'),
    path('beapi/add_route_spoke', add_route_spoke, name='add_route_spoke'),
    path('beapi/get_pbr_info_spoke', get_pbr_info_spoke, name='get_pbr_info_spoke'),
    path('beapi/addstaticroute_hub', addstaticroute_hub, name='addstaticroute_hub'),
    path('beapi/deletestaticroute_hub', delstaticroute_hub, name='delstaticroute_hub'),
    path('beapi/del_staticroute_spoke', del_staticroute_spoke, name='del_staticroute_spoke'),
    path('beapi/get_interface_details_hub', get_interface_details_hub, name='get_interface_details_hub'),
    path('beapi/add_cisco_hub', add_cisco_hub, name='add_cisco_hub'),
    path('beapi/get_configured_hub', get_configured_hub, name='get_configured_hub'),
    path('beapi/hub_info', hub_info, name='hub_info'),
    path('beapi/get_ciscospoke_config', get_ciscospoke_config, name='get_ciscospoke_config'),
    path('beapi/get_ciscohub_config', get_ciscohub_config, name='get_ciscohub_config'),
    path('beapi/create_vlan_interface_hub', create_vlan_interface_hub, name='create_vlan_interface_hub'),
    path('beapi/create_sub_interface_hub', create_sub_interface_hub, name='create_sub_interface_hub'),
    path('beapi/create_loopback_interface_hub', create_loopback_interface_hub, name='create_loopback_interface_hub'),
    path('beapi/vlan_interface_delete_hub', vlan_interface_delete_hub, name='vlan_interface_delete_hub'),
    path('beapi/create_tunnel_interface_hub', create_tunnel_interface_hub, name='create_tunnel_interface_hub'),
    path('beapi/create_loopback_interface_spoke', create_loopback_interface_spoke, name='create_loopback_interface_spoke'),
    path('beapi/create_sub_interface_spoke', create_sub_interface_spoke, name='create_sub_interface_spoke'),
    path('beapi/create_tunnel_interface_spoke', create_tunnel_interface_spoke, name='create_tunnel_interface_spoke'),
    path('beapi/interface_config_hub', interface_config_hub, name='interface_config_hub'),
    path('beapi/change_password', change_password, name='change_password'),
    path('beapi/get_microtekspoke_config', get_microtekspoke_config, name='get_microtekspoke_config'),
    path('beapi/traffic_report',traffic_report, name='traffic_report'),
    path('beapi/get_robustelspoke_config', get_robustelspoke_config, name='get_robustelspoke_config'),
    path('beapi/logfile_content', logfile_content, name='logfile_content'),

    # Swagger & Redoc URLs
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('beapi/swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('beapi/redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
