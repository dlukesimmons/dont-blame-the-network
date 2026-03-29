import csv
import io
import json
import subprocess

from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_ipv46_address
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_POST

from credentials.models import SNMPProfile, SSHProfile, HTTPSProfile
from .models import NetworkDevice, Server, _STATUS
from .forms import NetworkDeviceForm, ServerForm


# ---------------------------------------------------------------------------
# Connectivity test helpers
# ---------------------------------------------------------------------------

def _device_ip(device):
    return str(device.primary_ip or device.management_ip or '') or None


def _snmp_test(profile, ip):
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
    cmd += [ip, '1.3.6.1.2.1.1.5.0', '1.3.6.1.2.1.1.1.0']
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Timed out — no response from device.'}
    if r.returncode != 0:
        raw_err = (r.stderr or r.stdout).strip()
        err = raw_err.split('\n')[0] if raw_err else 'No response from device.'
        return {'success': False, 'error': err}
    lines = [l.strip().strip('"') for l in r.stdout.strip().splitlines() if l.strip()]
    return {'success': True, 'sys_name': lines[0] if lines else '', 'sys_desc': lines[1] if len(lines) > 1 else ''}


def _ssh_test(profile, ip):
    try:
        import paramiko
    except ImportError:
        return {'success': False, 'error': 'paramiko not installed.'}
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(hostname=ip, port=profile.port, username=profile.username,
                  timeout=10, banner_timeout=10, auth_timeout=10,
                  look_for_keys=False, allow_agent=False)
    if profile.auth_method == SSHProfile.METHOD_KEY:
        pkey = None
        for klass in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey]:
            try:
                pkey = klass.from_private_key(io.StringIO(profile.private_key)); break
            except Exception:
                continue
        if pkey is None:
            return {'success': False, 'error': 'Could not parse private key.'}
        kwargs['pkey'] = pkey
    else:
        kwargs['password'] = profile.password
    try:
        client.connect(**kwargs)
        transport = client.get_transport()
        banner = (transport.remote_version if transport else '') or ''
        client.close()
        return {'success': True, 'banner': banner}
    except paramiko.AuthenticationException:
        return {'success': False, 'error': 'Authentication failed.'}
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
    devices = NetworkDevice.objects.prefetch_related('snmp_profiles', 'ssh_profiles', 'https_profiles')
    if q:
        devices = devices.filter(name__icontains=q) | \
                  devices.filter(primary_ip__icontains=q) | \
                  devices.filter(management_ip__icontains=q)
    return render(request, 'inventory/network_list.html', {
        'devices':        devices,
        'q':              q,
        'snmp_profiles':  SNMPProfile.objects.all(),
        'ssh_profiles':   SSHProfile.objects.all(),
        'https_profiles': HTTPSProfile.objects.all(),
    })


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
        'form': form, 'title': f'Edit: {device.name}', 'action': 'Save Changes', 'device': device,
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
# CSV import
# ---------------------------------------------------------------------------

@login_required
def network_import_template(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="network_devices_import.csv"'
    writer = csv.writer(response)
    writer.writerow([
        'name', 'primary_ip', 'management_ip',
        'device_type', 'status',
        'manufacturer', 'model', 'serial_number', 'firmware_version',
        'location', 'description',
        'snmp_profiles', 'ssh_profiles', 'https_profiles',
    ])
    # Example rows — device_type choices: router switch firewall ap load_balancer vpn ups other
    # status choices: active inactive decommissioned in_stock
    # profile columns: comma-separated profile names that already exist in the system
    writer.writerow([
        'core-switch-01', '10.0.0.1', '',
        'switch', 'active',
        'Cisco', 'Catalyst 9300', 'FDO12345678', '17.9.3',
        'Server Room A', 'Core distribution switch',
        '', '', '',
    ])
    writer.writerow([
        'firewall-01', '10.0.0.254', '10.0.0.254',
        'firewall', 'active',
        'Palo Alto', 'PA-220', '', '10.2.5',
        'DC Edge', 'Perimeter firewall',
        'My-SNMP-Profile', 'My-SSH-Profile', '',
    ])
    return response


@login_required
@require_POST
def network_import(request):
    csv_file = request.FILES.get('csv_file')
    if not csv_file:
        messages.error(request, 'No file selected.')
        return redirect('network_list')

    try:
        decoded = csv_file.read().decode('utf-8-sig')
    except UnicodeDecodeError:
        messages.error(request, 'File encoding not supported — please save as UTF-8.')
        return redirect('network_list')

    reader = csv.DictReader(io.StringIO(decoded))

    if not reader.fieldnames or 'name' not in [f.strip() for f in reader.fieldnames]:
        messages.error(request, 'Invalid CSV — a "name" column is required.')
        return redirect('network_list')

    valid_types    = {k for k, _ in NetworkDevice.DEVICE_TYPES}
    valid_statuses = {k for k, _ in _STATUS}

    def col(row, key):
        return (row.get(key) or '').strip()

    def safe_ip(val):
        val = val.strip()
        if not val:
            return None
        try:
            validate_ipv46_address(val)
            return val
        except DjangoValidationError:
            return None

    created, skipped, row_errors = 0, 0, []

    for i, row in enumerate(reader, start=2):
        name = col(row, 'name')
        if not name:
            row_errors.append(f'Row {i}: missing name — skipped.')
            skipped += 1
            continue

        if NetworkDevice.objects.filter(name=name).exists():
            row_errors.append(f'Row {i}: "{name}" already exists — skipped.')
            skipped += 1
            continue

        dtype  = col(row, 'device_type').lower()
        status = col(row, 'status').lower()

        device = NetworkDevice(
            name             = name,
            primary_ip       = safe_ip(col(row, 'primary_ip')),
            management_ip    = safe_ip(col(row, 'management_ip')),
            device_type      = dtype  if dtype  in valid_types    else '',
            status           = status if status in valid_statuses else 'active',
            manufacturer     = col(row, 'manufacturer'),
            model            = col(row, 'model'),
            serial_number    = col(row, 'serial_number'),
            firmware_version = col(row, 'firmware_version'),
            location         = col(row, 'location'),
            description      = col(row, 'description'),
        )

        try:
            device.save()
        except Exception as e:
            row_errors.append(f'Row {i}: "{name}" save failed — {e}')
            skipped += 1
            continue

        for csv_col, model_cls, attr in [
            ('snmp_profiles',  SNMPProfile,  'snmp_profiles'),
            ('ssh_profiles',   SSHProfile,   'ssh_profiles'),
            ('https_profiles', HTTPSProfile, 'https_profiles'),
        ]:
            for pname in [n.strip() for n in col(row, csv_col).split(',') if n.strip()]:
                try:
                    getattr(device, attr).add(model_cls.objects.get(name=pname))
                except model_cls.DoesNotExist:
                    row_errors.append(f'Row {i}: profile "{pname}" not found — skipped.')

        created += 1

    if created:
        messages.success(request, f'Import complete: {created} device{"s" if created != 1 else ""} created, {skipped} skipped.')
    else:
        messages.warning(request, f'No devices imported. {skipped} row{"s" if skipped != 1 else ""} skipped.')

    for err in row_errors[:20]:
        messages.warning(request, err)
    if len(row_errors) > 20:
        messages.warning(request, f'… and {len(row_errors) - 20} more warnings not shown.')

    return redirect('network_list')


# ---------------------------------------------------------------------------
# Bulk profile assignment
# ---------------------------------------------------------------------------

@login_required
@require_POST
def network_bulk_assign(request):
    body       = json.loads(request.body)
    device_ids = body.get('device_ids', [])
    snmp_ids   = body.get('snmp_ids',   [])
    ssh_ids    = body.get('ssh_ids',    [])
    https_ids  = body.get('https_ids',  [])
    action     = body.get('action', 'add')

    if not device_ids:
        return JsonResponse({'error': 'No devices selected.'}, status=400)
    if not any([snmp_ids, ssh_ids, https_ids]):
        return JsonResponse({'error': 'No profiles selected.'}, status=400)

    devices        = NetworkDevice.objects.filter(pk__in=device_ids)
    snmp_profiles  = list(SNMPProfile.objects.filter(pk__in=snmp_ids))
    ssh_profiles   = list(SSHProfile.objects.filter(pk__in=ssh_ids))
    https_profiles = list(HTTPSProfile.objects.filter(pk__in=https_ids))

    for device in devices:
        if action == 'remove':
            if snmp_profiles:  device.snmp_profiles.remove(*snmp_profiles)
            if ssh_profiles:   device.ssh_profiles.remove(*ssh_profiles)
            if https_profiles: device.https_profiles.remove(*https_profiles)
        else:
            if snmp_profiles:  device.snmp_profiles.add(*snmp_profiles)
            if ssh_profiles:   device.ssh_profiles.add(*ssh_profiles)
            if https_profiles: device.https_profiles.add(*https_profiles)

    return JsonResponse({'success': True, 'count': devices.count(), 'action': action})


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
        'form': form, 'title': f'Edit: {server.name}', 'action': 'Save Changes', 'server': server,
    })


@login_required
@require_POST
def server_delete(request, pk):
    server = get_object_or_404(Server, pk=pk)
    name = server.name
    server.delete()
    messages.success(request, f'Server "{name}" deleted.')
    return redirect('server_list')
