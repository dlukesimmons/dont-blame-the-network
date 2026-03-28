from django import forms
from .models import SNMPProfile, SSHProfile, HTTPSProfile

_FC  = 'form-control'
_FS  = 'form-select'
_PW  = {'class': _FC, 'placeholder': 'Leave blank to keep existing'}
_PW2 = {'class': _FC, 'placeholder': 'Leave blank to keep existing', 'rows': 6,
        'style': 'font-family:monospace;font-size:0.8rem;'}


def _keep_existing(form, fields):
    """
    For edit forms: if a secret field is submitted blank, restore the
    original encrypted value from the database so it isn't overwritten.
    """
    if not form.instance.pk:
        return
    original = form.instance.__class__.objects.get(pk=form.instance.pk)
    for field in fields:
        if not form.cleaned_data.get(field):
            form.instance.__dict__[field] = original.__dict__.get(field, '')


class SNMPProfileForm(forms.ModelForm):
    community     = forms.CharField(required=False,
                        widget=forms.PasswordInput(render_value=False, attrs=_PW))
    auth_password = forms.CharField(required=False,
                        widget=forms.PasswordInput(render_value=False, attrs=_PW))
    priv_password = forms.CharField(required=False,
                        widget=forms.PasswordInput(render_value=False, attrs=_PW))

    class Meta:
        model  = SNMPProfile
        fields = ['name', 'version', 'community',
                  'v3_username', 'auth_protocol', 'auth_password',
                  'priv_protocol', 'priv_password', 'notes']
        widgets = {
            'name':          forms.TextInput(attrs={'class': _FC}),
            'version':       forms.Select(attrs={'class': _FS}),
            'v3_username':   forms.TextInput(attrs={'class': _FC}),
            'auth_protocol': forms.Select(attrs={'class': _FS}),
            'priv_protocol': forms.Select(attrs={'class': _FS}),
            'notes':         forms.Textarea(attrs={'class': _FC, 'rows': 3}),
        }

    def save(self, commit=True):
        instance = super().save(commit=False)
        _keep_existing(self, ['community', 'auth_password', 'priv_password'])
        if commit:
            instance.save()
        return instance


class SSHProfileForm(forms.ModelForm):
    password    = forms.CharField(required=False,
                      widget=forms.PasswordInput(render_value=False, attrs=_PW))
    private_key = forms.CharField(required=False,
                      widget=forms.Textarea(attrs=_PW2))

    class Meta:
        model  = SSHProfile
        fields = ['name', 'username', 'port', 'auth_method', 'password', 'private_key', 'notes']
        widgets = {
            'name':        forms.TextInput(attrs={'class': _FC}),
            'username':    forms.TextInput(attrs={'class': _FC}),
            'port':        forms.NumberInput(attrs={'class': _FC}),
            'auth_method': forms.Select(attrs={'class': _FS}),
            'notes':       forms.Textarea(attrs={'class': _FC, 'rows': 3}),
        }

    def save(self, commit=True):
        instance = super().save(commit=False)
        _keep_existing(self, ['password', 'private_key'])
        if commit:
            instance.save()
        return instance


class HTTPSProfileForm(forms.ModelForm):
    password  = forms.CharField(required=False,
                    widget=forms.PasswordInput(render_value=False, attrs=_PW))
    api_token = forms.CharField(required=False,
                    widget=forms.PasswordInput(render_value=False, attrs=_PW))

    class Meta:
        model  = HTTPSProfile
        fields = ['name', 'base_url', 'username', 'password', 'api_token', 'verify_ssl', 'notes']
        widgets = {
            'name':     forms.TextInput(attrs={'class': _FC}),
            'base_url': forms.TextInput(attrs={'class': _FC}),
            'username': forms.TextInput(attrs={'class': _FC}),
            'notes':    forms.Textarea(attrs={'class': _FC, 'rows': 3}),
        }

    def save(self, commit=True):
        instance = super().save(commit=False)
        _keep_existing(self, ['password', 'api_token'])
        if commit:
            instance.save()
        return instance
