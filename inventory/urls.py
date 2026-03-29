from django.urls import path
from . import views

urlpatterns = [
    # Network Devices
    path('network/',                    views.network_list,   name='network_list'),
    path('network/add/',                views.network_add,    name='network_add'),
    path('network/<int:pk>/',           views.network_detail, name='network_detail'),
    path('network/<int:pk>/edit/',      views.network_edit,   name='network_edit'),
    path('network/<int:pk>/delete/',    views.network_delete, name='network_delete'),

    # Connectivity tests
    path('network/<int:device_pk>/test-snmp/<int:profile_pk>/', views.test_snmp, name='test_snmp'),
    path('network/<int:device_pk>/test-ssh/<int:profile_pk>/',  views.test_ssh,  name='test_ssh'),

    # Servers
    path('servers/',                    views.server_list,    name='server_list'),
    path('servers/add/',                views.server_add,     name='server_add'),
    path('servers/<int:pk>/',           views.server_detail,  name='server_detail'),
    path('servers/<int:pk>/edit/',      views.server_edit,    name='server_edit'),
    path('servers/<int:pk>/delete/',    views.server_delete,  name='server_delete'),
]
