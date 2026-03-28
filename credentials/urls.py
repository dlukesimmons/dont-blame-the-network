from django.urls import path
from . import views

urlpatterns = [
    # SNMP
    path('snmp/',              views.snmp_list,   name='snmp_list'),
    path('snmp/add/',          views.snmp_add,    name='snmp_add'),
    path('snmp/<int:pk>/edit/', views.snmp_edit,  name='snmp_edit'),
    path('snmp/<int:pk>/delete/', views.snmp_delete, name='snmp_delete'),

    # SSH
    path('ssh/',               views.ssh_list,    name='ssh_list'),
    path('ssh/add/',           views.ssh_add,     name='ssh_add'),
    path('ssh/<int:pk>/edit/', views.ssh_edit,    name='ssh_edit'),
    path('ssh/<int:pk>/delete/', views.ssh_delete, name='ssh_delete'),

    # HTTPS
    path('https/',               views.https_list,   name='https_list'),
    path('https/add/',           views.https_add,    name='https_add'),
    path('https/<int:pk>/edit/', views.https_edit,   name='https_edit'),
    path('https/<int:pk>/delete/', views.https_delete, name='https_delete'),
]
