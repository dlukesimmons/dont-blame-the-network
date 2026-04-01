from django.urls import path
from . import views

urlpatterns = [
    path('icmp-scan/',        views.icmp_scan,       name='icmp_scan'),
    path('icmp-scan/run/',    views.icmp_scan_run,   name='icmp_scan_run'),
    path('tcp-scan/run/',     views.tcp_scan_run,    name='tcp_scan_run'),
    path('snmp-scan/',        views.snmp_scan,       name='snmp_scan'),
    path('snmp-scan/run/',    views.snmp_scan_run,   name='snmp_scan_run'),
    path('bulk-scan/',        views.bulk_scan,        name='bulk_scan'),
    path('bulk-scan/stream/', views.bulk_scan_stream, name='bulk_scan_stream'),
]
