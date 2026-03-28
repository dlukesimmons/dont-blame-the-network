from django.db import models


_STATUS = [
    ('active',         'Active'),
    ('inactive',       'Inactive'),
    ('decommissioned', 'Decommissioned'),
    ('in_stock',       'In Stock'),
]


class NetworkDevice(models.Model):
    DEVICE_TYPES = [
        ('',             '— Unknown —'),
        ('router',       'Router'),
        ('switch',       'Switch'),
        ('firewall',     'Firewall'),
        ('ap',           'Access Point'),
        ('load_balancer','Load Balancer'),
        ('vpn',          'VPN Concentrator'),
        ('ups',          'UPS / PDU'),
        ('other',        'Other'),
    ]

    # Required
    name = models.CharField(max_length=200, unique=True)

    # Addressing
    primary_ip    = models.GenericIPAddressField(protocol='both', blank=True, null=True)
    management_ip = models.GenericIPAddressField(protocol='both', blank=True, null=True)

    # Classification
    device_type = models.CharField(max_length=20, choices=DEVICE_TYPES, blank=True)
    status      = models.CharField(max_length=20, choices=_STATUS, default='active')

    # Hardware identity
    manufacturer     = models.CharField(max_length=100, blank=True)
    model            = models.CharField(max_length=100, blank=True)
    serial_number    = models.CharField(max_length=100, blank=True)
    firmware_version = models.CharField(max_length=100, blank=True)

    # Location & notes
    location    = models.CharField(max_length=200, blank=True)
    description = models.TextField(blank=True)

    # Authentication profiles
    snmp_profiles  = models.ManyToManyField(
        'credentials.SNMPProfile',  blank=True, related_name='network_devices')
    ssh_profiles   = models.ManyToManyField(
        'credentials.SSHProfile',   blank=True, related_name='network_devices')
    https_profiles = models.ManyToManyField(
        'credentials.HTTPSProfile', blank=True, related_name='network_devices')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering     = ['name']
        verbose_name = 'Network Device'

    def __str__(self):
        return self.name


class Server(models.Model):
    SERVER_TYPES = [
        ('',          '— Unknown —'),
        ('physical',  'Physical'),
        ('vm',        'Virtual Machine'),
        ('container', 'Container Host'),
        ('other',     'Other'),
    ]
    OS_TYPES = [
        ('',        '— Unknown —'),
        ('linux',   'Linux'),
        ('windows', 'Windows'),
        ('esxi',    'VMware ESXi'),
        ('other',   'Other'),
    ]

    # Required
    name = models.CharField(max_length=200, unique=True)

    # Addressing
    primary_ip    = models.GenericIPAddressField(protocol='both', blank=True, null=True)
    management_ip = models.GenericIPAddressField(protocol='both', blank=True, null=True)

    # Classification
    server_type = models.CharField(max_length=20, choices=SERVER_TYPES, blank=True)
    status      = models.CharField(max_length=20, choices=_STATUS, default='active')

    # OS
    os_type    = models.CharField(max_length=20, choices=OS_TYPES, blank=True)
    os_version = models.CharField(max_length=100, blank=True)

    # Hardware identity
    manufacturer  = models.CharField(max_length=100, blank=True)
    model         = models.CharField(max_length=100, blank=True)
    serial_number = models.CharField(max_length=100, blank=True)

    # Location & notes
    location    = models.CharField(max_length=200, blank=True)
    description = models.TextField(blank=True)

    # Authentication profiles (no SNMP for servers typically)
    ssh_profiles   = models.ManyToManyField(
        'credentials.SSHProfile',   blank=True, related_name='servers')
    https_profiles = models.ManyToManyField(
        'credentials.HTTPSProfile', blank=True, related_name='servers')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering     = ['name']
        verbose_name = 'Server'

    def __str__(self):
        return self.name
