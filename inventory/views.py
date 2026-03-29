import io
import subprocess

from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_POST

from credentials.models import SNMPProfile, SSHProfile
from .models import NetworkDevice, Server
from .forms import NetworkDeviceForm, ServerForm


# ---------------------------------------------------------------------------
# Connectivity test helpers
# ---------------------------------------------------------------------------

def _device_ip(device):
    """Return the best IP to test against, or None."""
    return str(device.primary_ip or device.management_ip or '') or None


def _snmp_test(profile, ip):
    """Run snmpget for sysName + sysDescr. Returns dict with success/error."""
    base = ['snmpget', '-r', '1', '-t', '5', '-Oqv']

    if profile.version == SNMPProfile.V3:
        has_auth = bool(profile.auth_protocol and profile.auth_password)
        has_priv = bool(profile.priv_protocol and profile.priv_password)
        sec_level = 'authPriv' if has_priv else ('authNoPriv' if has_auth else 'noAuthNoPriv')
        cmd = base + ['-v3', '-l', sec_level, '-u', profile.v3_username]
        if has_auth:
            cmd += ['-a', profile.auth_protocol, '-A', profile.auth_password]
        if has_priv:
            cmd += ['-x', profile.priv_protocol, '-X', profile.priv_password]
    else:
        version_flag = '1' if profile.version == SNMPProfile.V1 else '2c'
        cmd = base + [f'-v{version_flag}', '-c', profile.community]

    # Fetch sysName and sysDescr
    cmd += [ip, '1.3.6.1.2.1.1.5.0', '1.3.6.1.2.1.1.1.0']

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Timed out — no response from device.'}

    if r.returncode != 0:
        raw_err = (r.stderr or r.stdout).strip()
        # Strip noisy snmpget prefix
        err = raw_err.split('\n')[0] if raw_err else 'No response from device.'
        return {'success': False, 'error': err}

    lines = [l.strip().strip('"') for l in r.stdout.strip().splitlines() if l.strip()]
    return {
        'success':  True,
        'sys_name': lines[0] if lines else '',
        'sys_desc': lines[1] if len(lines) > 1 else '',
    }


def _ssh_test(profile, ip):
    """Attempt an SSH connection. Returns dict with success/error."""
    try:
        import paramiko
    except ImportError:
        return {'success': False, 'error': 'paramiko not installed.'}

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    kwargs = dict(
        hostname=ip,
        port=profile.port,
        username=profile.username,
        timeout=10,
        banner_timeout=10,
        auth_timeout=10,
        look_for_keys=False,
        allow_agent=False,
    )

    if profile.auth_method == SSHProfile.METHOD_KEY:
        key_classes = [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey]
        pkey = None
        for klass in key_classes:
            try:
                pkey = klass.from_private_key(io.StringIO(profile.private_key))
                break
            except Exception:
                continue
        if pkey is None:
            return {'success': False, 'error': 'Could not parse private key (unsupported type or passphrase required).'}
        kwargs['pkey'] = pkey
    else:
        kwargs['password'] = profile.password

    try:
        client.connect(**kwargs)
        banner = ''
        transport = client.get_transport()
        if transport:
            banner = transport.remote_version or ''
        client.close()
        return {'success': True, 'banner': banner}
    except paramiko.AuthenticationException:
        return {'success': False, 'error': 'Authentication failed — check username / password / key.'}
    except paramiko.SSHException as e:
        return {'success': False, 'error': f'SSH error: {e}'}
    except OSError as e:
        return {'success': False, 'error': f'Connection failed: {e}'}
    except Exception as e:
        return {'success': False, 'error': str(e)}


# ---------------------------------------------------------------------------
# Network Devices
# ---------------------------------------------------------------------------

@login_required
def network_list(request):
    q = request.GET.get('q', '').strip()
    devices = NetworkDevice.objects.all()
    if q:
        devices = devices.filter(name__icontains=q) | \
                  devices.filter(primary_ip__icontains=q) | \
                  devices.filter(management_ip__icontains=q)
    return render(request, 'inventory/network_list.html', {'devices': devices, 'q': q})


@login_required
def network_add(request):
    form = NetworkDeviceForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        device = form.save()
        messages.success(request, f'Network device "{device.name}" added.')
        return redirect('network_list')
    return render(request, 'inventory/network_form.html', {
        'form': form, 'title': 'Add Network Device', 'action': 'Add Device',
    })


@login_required
def network_detail(request, pk):
    device = get_object_or_404(NetworkDevice, pk=pk)
    return render(request, 'inventory/network_detail.html', {'device': device})


@login_required
def network_edit(request, pk):
    device = get_object_or_404(NetworkDevice, pk=pk)
    form = NetworkDeviceForm(request.POST or None, instance=device)
    if request.method == 'POST' and form.is_valid():
        form.save()
        messages.success(request, f'Network device "{device.name}" updated.')
        return redirect('network_detail', pk=pk)
    return render(request, 'inventory/network_form.html', {
        'form': form, 'title': f'Edit: {device.name}', 'action': 'Save Changes',
        'device': device,
    })


@login_required
@require_POST
def network_delete(request, pk):
    device = get_object_or_404(NetworkDevice, pk=pk)
    name = device.name
    device.delete()
    messages.success(request, f'Network device "{name}" deleted.')
    return redirect('network_list')


# ---------------------------------------------------------------------------
# Connectivity tests (AJAX)
# ---------------------------------------------------------------------------

@login_required
@require_POST
def test_snmp(request, device_pk, profile_pk):
    device  = get_object_or_404(NetworkDevice, pk=device_pk)
    profile = get_object_or_404(SNMPProfile, pk=profile_pk)
    ip = _device_ip(device)
    if not ip:
        return JsonResponse({'success': False, 'error': 'No IP address configured on this device.'})
    return JsonResponse(_snmp_test(profile, ip))


@login_required
@require_POST
def test_ssh(request, device_pk, profile_pk):
    device  = get_object_or_404(NetworkDevice, pk=device_pk)
    profile = get_object_or_404(SSHProfile, pk=profile_pk)
    ip = _device_ip(device)
    if not ip:
        return JsonResponse({'success': False, 'error': 'No IP address configured on this device.'})
    return JsonResponse(_ssh_test(profile, ip))


# ---------------------------------------------------------------------------
# Servers
# ---------------------------------------------------------------------------

@login_required
def server_list(request):
    q = request.GET.get('q', '').strip()
    servers = Server.objects.all()
    if q:
        servers = servers.filter(name__icontains=q) | \
                  servers.filter(primary_ip__icontains=q) | \
                  servers.filter(management_ip__icontains=q)
    return render(request, 'inventory/server_list.html', {'servers': servers, 'q': q})


@login_required
def server_add(request):
    form = ServerForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        server = form.save()
        messages.success(request, f'Server "{server.name}" added.')
        return redirect('server_list')
    return render(request, 'inventory/server_form.html', {
        'form': form, 'title': 'Add Server', 'action': 'Add Server',
    })


@login_required
def server_detail(request, pk):
    server = get_object_or_404(Server, pk=pk)
    return render(request, 'inventory/server_detail.html', {'server': server})


@login_required
def server_edit(request, pk):
    server = get_object_or_404(Server, pk=pk)
    form = ServerForm(request.POST or None, instance=server)
    if request.method == 'POST' and form.is_valid():
        form.save()
        messages.success(request, f'Server "{server.name}" updated.')
        return redirect('server_detail', pk=pk)
    return render(request, 'inventory/server_form.html', {
        'form': form, 'title': f'Edit: {server.name}', 'action': 'Save Changes',
        'server': server,
    })


@login_required
@require_POST
def server_delete(request, pk):
    server = get_object_or_404(Server, pk=pk)
    name = server.name
    server.delete()
    messages.success(request, f'Server "{name}" deleted.')
    return redirect('server_list')
