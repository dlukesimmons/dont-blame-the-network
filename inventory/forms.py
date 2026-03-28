from django import forms
from .models import NetworkDevice, Server
from credentials.models import SNMPProfile, SSHProfile, HTTPSProfile

_FC = 'form-control'
_FS = 'form-select'

_CB_ATTRS = {'class': 'profile-checkbox-list'}


class _ProfileCheckboxSelect(forms.CheckboxSelectMultiple):
    """Thin wrapper so we can target it in CSS/JS."""


class NetworkDeviceForm(forms.ModelForm):
    snmp_profiles = forms.ModelMultipleChoiceField(
        queryset=SNMPProfile.objects.all(),
        required=False,
        widget=_ProfileCheckboxSelect(),
        label='SNMP Profiles',
    )
    ssh_profiles = forms.ModelMultipleChoiceField(
        queryset=SSHProfile.objects.all(),
        required=False,
        widget=_ProfileCheckboxSelect(),
        label='SSH Profiles',
    )
    https_profiles = forms.ModelMultipleChoiceField(
        queryset=HTTPSProfile.objects.all(),
        required=False,
        widget=_ProfileCheckboxSelect(),
        label='HTTPS Profiles',
    )

    class Meta:
        model  = NetworkDevice
        fields = [
            'name', 'primary_ip', 'management_ip',
            'device_type', 'status',
            'manufacturer', 'model', 'serial_number', 'firmware_version',
            'location', 'description',
            'snmp_profiles', 'ssh_profiles', 'https_profiles',
        ]
        widgets = {
            'name':             forms.TextInput(attrs={'class': _FC}),
            'primary_ip':       forms.TextInput(attrs={'class': _FC, 'placeholder': 'e.g. 10.0.0.1'}),
            'management_ip':    forms.TextInput(attrs={'class': _FC, 'placeholder': 'e.g. 10.0.0.1'}),
            'device_type':      forms.Select(attrs={'class': _FS}),
            'status':           forms.Select(attrs={'class': _FS}),
            'manufacturer':     forms.TextInput(attrs={'class': _FC}),
            'model':            forms.TextInput(attrs={'class': _FC}),
            'serial_number':    forms.TextInput(attrs={'class': _FC}),
            'firmware_version': forms.TextInput(attrs={'class': _FC}),
            'location':         forms.TextInput(attrs={'class': _FC}),
            'description':      forms.Textarea(attrs={'class': _FC, 'rows': 3}),
        }


class ServerForm(forms.ModelForm):
    ssh_profiles = forms.ModelMultipleChoiceField(
        queryset=SSHProfile.objects.all(),
        required=False,
        widget=_ProfileCheckboxSelect(),
        label='SSH Profiles',
    )
    https_profiles = forms.ModelMultipleChoiceField(
        queryset=HTTPSProfile.objects.all(),
        required=False,
        widget=_ProfileCheckboxSelect(),
        label='HTTPS Profiles',
    )

    class Meta:
        model  = Server
        fields = [
            'name', 'primary_ip', 'management_ip',
            'server_type', 'status',
            'os_type', 'os_version',
            'manufacturer', 'model', 'serial_number',
            'location', 'description',
            'ssh_profiles', 'https_profiles',
        ]
        widgets = {
            'name':          forms.TextInput(attrs={'class': _FC}),
            'primary_ip':    forms.TextInput(attrs={'class': _FC, 'placeholder': 'e.g. 10.0.0.10'}),
            'management_ip': forms.TextInput(attrs={'class': _FC, 'placeholder': 'e.g. 10.0.0.10'}),
            'server_type':   forms.Select(attrs={'class': _FS}),
            'status':        forms.Select(attrs={'class': _FS}),
            'os_type':       forms.Select(attrs={'class': _FS}),
            'os_version':    forms.TextInput(attrs={'class': _FC}),
            'manufacturer':  forms.TextInput(attrs={'class': _FC}),
            'model':         forms.TextInput(attrs={'class': _FC}),
            'serial_number': forms.TextInput(attrs={'class': _FC}),
            'location':      forms.TextInput(attrs={'class': _FC}),
            'description':   forms.Textarea(attrs={'class': _FC, 'rows': 3}),
        }
