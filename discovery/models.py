from django.conf import settings
from django.db import models


class DiscoverySnapshot(models.Model):
    STATUS_PENDING  = 'pending'
    STATUS_RUNNING  = 'running'
    STATUS_COMPLETE = 'complete'
    STATUS_CHOICES  = [
        (STATUS_PENDING,  'Pending'),
        (STATUS_RUNNING,  'Running'),
        (STATUS_COMPLETE, 'Complete'),
    ]

    name          = models.CharField(max_length=200)
    site          = models.CharField(max_length=200, blank=True)   # '' = all sites
    status        = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    device_count  = models.PositiveIntegerField(default=0)
    success_count = models.PositiveIntegerField(default=0)
    created_at    = models.DateTimeField(auto_now_add=True)
    created_by    = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.name


class DeviceDiscoveryResult(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_SUCCESS = 'success'
    STATUS_FAILED  = 'failed'
    STATUS_NO_SSH  = 'no_ssh'
    STATUS_NO_IP   = 'no_ip'
    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_SUCCESS, 'Success'),
        (STATUS_FAILED,  'Failed'),
        (STATUS_NO_SSH,  'No SSH Profile'),
        (STATUS_NO_IP,   'No IP Address'),
    ]

    snapshot     = models.ForeignKey(
        DiscoverySnapshot, on_delete=models.CASCADE, related_name='results'
    )
    device       = models.ForeignKey(
        'inventory.NetworkDevice', on_delete=models.CASCADE, related_name='discovery_results'
    )
    status       = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    arp_output   = models.TextField(blank=True)
    mac_output   = models.TextField(blank=True)
    error        = models.TextField(blank=True)
    collected_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering     = ['device__name']
        unique_together = [['snapshot', 'device']]

    def __str__(self):
        return f"{self.snapshot.name} — {self.device.name}"
