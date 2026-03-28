from django.db import models
from .fields import EncryptedTextField


class SNMPProfile(models.Model):
    V1  = 'v1'
    V2C = 'v2c'
    V3  = 'v3'
    VERSION_CHOICES = [(V1, 'v1'), (V2C, 'v2c'), (V3, 'v3')]

    AUTH_CHOICES = [
        ('', 'None'),
        ('MD5',     'MD5'),
        ('SHA',     'SHA-1'),
        ('SHA-224', 'SHA-224'),
        ('SHA-256', 'SHA-256'),
        ('SHA-384', 'SHA-384'),
        ('SHA-512', 'SHA-512'),
    ]
    PRIV_CHOICES = [
        ('',        'None'),
        ('DES',     'DES'),
        ('AES',     'AES-128'),
        ('AES-192', 'AES-192'),
        ('AES-256', 'AES-256'),
    ]

    name          = models.CharField(max_length=100, unique=True)
    version       = models.CharField(max_length=4, choices=VERSION_CHOICES, default=V2C)
    # v1 / v2c
    community     = EncryptedTextField(blank=True, default='')
    # v3
    v3_username   = models.CharField(max_length=100, blank=True)
    auth_protocol = models.CharField(max_length=10, choices=AUTH_CHOICES, blank=True)
    auth_password = EncryptedTextField(blank=True, default='')
    priv_protocol = models.CharField(max_length=10, choices=PRIV_CHOICES, blank=True)
    priv_password = EncryptedTextField(blank=True, default='')

    notes      = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering     = ['name']
        verbose_name = 'SNMP Profile'

    def __str__(self):
        return f'{self.name} ({self.version})'


class SSHProfile(models.Model):
    METHOD_PASSWORD = 'password'
    METHOD_KEY      = 'key'
    METHOD_CHOICES  = [(METHOD_PASSWORD, 'Password'), (METHOD_KEY, 'Private Key')]

    name        = models.CharField(max_length=100, unique=True)
    username    = models.CharField(max_length=100)
    port        = models.PositiveIntegerField(default=22)
    auth_method = models.CharField(max_length=10, choices=METHOD_CHOICES, default=METHOD_PASSWORD)
    password    = EncryptedTextField(blank=True, default='')
    private_key = EncryptedTextField(blank=True, default='')

    notes      = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering     = ['name']
        verbose_name = 'SSH Profile'

    def __str__(self):
        return f'{self.name} ({self.username}:{self.port})'


class HTTPSProfile(models.Model):
    name       = models.CharField(max_length=100, unique=True)
    base_url   = models.CharField(max_length=500, blank=True,
                                  help_text='e.g. https://device.local — used to build links in tools')
    username   = models.CharField(max_length=100, blank=True)
    password   = EncryptedTextField(blank=True, default='')
    api_token  = EncryptedTextField(blank=True, default='')
    verify_ssl = models.BooleanField(default=True)

    notes      = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering     = ['name']
        verbose_name = 'HTTPS Profile'

    def __str__(self):
        return self.name
