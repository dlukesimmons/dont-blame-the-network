import csv
import io
import json
import re
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


def _snmp_base_cmd(profile):
    """Return the snmpget base command list for a given profile (no OIDs, no host)."""
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
    return cmd


def _snmp_test(profile, ip):
    cmd = _snmp_base_cmd(profile) + [ip, '1.3.6.1.2.1.1.5.0', '1.3.6.1.2.1.1.1.0']
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


def _parse_sys_descr(desc):
    """Parse SNMP sysDescr to extract manufacturer hint and OS version string."""
    if not desc:
        return {}
    result = {}
    dl = desc.lower()

    # Manufacturer
    if 'cisco' in dl:
        result['manufacturer'] = 'Cisco'
    elif 'juniper' in dl:
        result['manufacturer'] = 'Juniper'
    elif dl.startswith('hp ') or ' hp ' in dl or 'hewlett' in dl:
        result['manufacturer'] = 'HP'
    elif 'aruba' in dl:
        result['manufacturer'] = 'Aruba'
    elif 'palo alto' in dl or 'pan-os' in dl:
        result['manufacturer'] = 'Palo Alto Networks'
    elif 'fortinet' in dl or 'fortigate' in dl or 'forticos' in dl:
        result['manufacturer'] = 'Fortinet'
    elif 'mikrotik' in dl or 'routeros' in dl:
        result['manufacturer'] = 'MikroTik'
    elif 'ubiquiti' in dl or 'edgeos' in dl or 'unifi' in dl:
        result['manufacturer'] = 'Ubiquiti'
    elif 'extreme' in dl:
        result['manufacturer'] = 'Extreme Networks'
    elif 'dell' in dl:
        result['manufacturer'] = 'Dell'
    elif 'netgear' in dl:
        result['manufacturer'] = 'Netgear'
    elif 'opengear' in dl:
        result['manufacturer'] = 'Opengear'
    elif 'apc' in dl or 'american power' in dl:
        result['manufacturer'] = 'APC'
    elif 'brocade' in dl:
        result['manufacturer'] = 'Brocade'

    # OS version — "Version X.Y.Z" pattern covers IOS, NX-OS, ASA, etc.
    m = re.search(r'[Vv]ersion\s+([\d][^\s,;]+)', desc)
    if m:
        result['version'] = m.group(1).rstrip(',.')
    # HP revision pattern: "revision KA.16.05"
    elif re.search(r'revision\s+([A-Z]{1,3}[\.\d]+)', desc, re.IGNORECASE):
        m2 = re.search(r'revision\s+([A-Z]{1,3}[\.\d]+)', desc, re.IGNORECASE)
        result['version'] = m2.group(1)

    return result


def _infer_device_type(desc):
    """Try to infer device_type choice value from sysDescr."""
    dl = (desc or '').lower()
    if any(k in dl for k in ['switch', 'catalyst', 'nexus', 'stackable', 'c9', 'ws-c']):
        return 'switch'
    if any(k in dl for k in ['router', ' asr', ' isr', ' crs', ' mx ', ' srx ']):
        return 'router'
    if any(k in dl for k in ['firewall', 'adaptive security', 'fortigate', 'palo alto',
                               'ftd', ' asa ', 'checkpoint']):
        return 'firewall'
    if any(k in dl for k in ['access point', 'wireless lan', ' ap ']):
        return 'ap'
    if any(k in dl for k in ['load balancer', 'big-ip', 'netscaler', 'citrix adc']):
        return 'load_balancer'
    return ''


# SNMP OIDs used for device inventory polling
_OID_SYS_DESCR    = '1.3.6.1.2.1.1.1.0'
_OID_SYS_NAME     = '1.3.6.1.2.1.1.5.0'
_OID_SYS_LOCATION = '1.3.6.1.2.1.1.6.0'
_OID_SYS_OBJECTID = '1.3.6.1.2.1.1.2.0'

# Entity MIB column OIDs (no .instance suffix — walked to find first valid entry).
# Using snmpwalk instead of snmpget .1 because different devices store the chassis
# entry at different indices (Firepower, WLC, etc. don't always use index 1).
_COL_ENT_SW_REV = '1.3.6.1.2.1.47.1.1.1.1.10'   # entPhysicalSoftwareRev
_COL_ENT_SERIAL = '1.3.6.1.2.1.47.1.1.1.1.11'   # entPhysicalSerialNum
_COL_ENT_MFG    = '1.3.6.1.2.1.47.1.1.1.1.12'   # entPhysicalMfgName
_COL_ENT_MODEL  = '1.3.6.1.2.1.47.1.1.1.1.13'   # entPhysicalModelName

# Vendor-specific OIDs for devices that don't support entity MIB.
# Each entry: (sysObjectID prefix, {model_oid, serial_oid, sw_rev_oid})
_VENDOR_OIDS = [
    # Opengear (enterprise 25049) — ogSystemMIB under .10.19.1
    ('1.3.6.1.4.1.25049', {
        'model':  '1.3.6.1.4.1.25049.10.19.1.5.0',   # ogSystemModelName (proper case)
        'serial': '1.3.6.1.4.1.25049.10.19.1.2.0',   # ogSystemSerialNumber
        'sw_rev': '1.3.6.1.4.1.25049.10.19.1.3.0',   # ogSystemFirmwareVersion
    }),
]

# Strings snmpget/snmpwalk return (rc=0) when an OID has no data
_SNMP_NULL = ('no such instance', 'no such object', 'no more variables', 'end of mib')


def _is_snmp_null(val):
    return bool(val) and any(val.strip().lower().startswith(s) for s in _SNMP_NULL)


def _snmp_clean(val):
    """Return '' if val is an SNMP error/null string, else return val unchanged."""
    return '' if _is_snmp_null(val) else (val or '')


def _snmp_update_device(device):
    """
    Try each assigned SNMP profile in order.  On first success, poll device
    inventory OIDs, update model fields, save, and return result dict.

    Returns dict with keys: success, profile, fields_updated, error.
    """
    ip = _device_ip(device)
    if not ip:
        return {'success': False, 'profile': None, 'fields_updated': {}, 'error': 'No IP configured'}

    profiles = list(device.snmp_profiles.all())
    if not profiles:
        return {'success': False, 'profile': None, 'fields_updated': {}, 'error': 'No SNMP profiles assigned'}

    def _get(oid, timeout=10):
        """snmpget a single OID. Returns clean string or '' on any error/null."""
        try:
            r = subprocess.run(base + [ip, oid], capture_output=True, text=True, timeout=timeout)
            if r.returncode == 0:
                return _snmp_clean(r.stdout.strip().strip('"'))
        except subprocess.TimeoutExpired:
            pass
        return ''

    def _walk_first(col_oid, timeout=12):
        """Walk an entity MIB column and return the first non-empty, non-null value.
        Uses snmpwalk so devices that store the chassis entry at any index work."""
        walk = ['snmpwalk'] + base[1:]   # swap snmpget → snmpwalk, keep flags
        try:
            r = subprocess.run(walk + [ip, col_oid], capture_output=True, text=True, timeout=timeout)
            for line in r.stdout.strip().splitlines():
                val = _snmp_clean(line.strip().strip('"'))
                if val:
                    return val
        except subprocess.TimeoutExpired:
            pass
        return ''

    last_error = ''
    for profile in profiles:
        base = _snmp_base_cmd(profile)

        # ── sysName — verify profile works first ─────────────────────────────
        try:
            probe = subprocess.run(base + [ip, _OID_SYS_NAME],
                                   capture_output=True, text=True, timeout=12)
            if probe.returncode != 0:
                raw = (probe.stderr or probe.stdout).strip()
                last_error = raw.split('\n')[0] if raw else 'No response'
                continue
            sys_name = _snmp_clean(probe.stdout.strip().strip('"'))
        except subprocess.TimeoutExpired:
            last_error = 'Timed out'
            continue

        # ── sysDescr — can be multi-line; join all output lines ──────────────
        try:
            rd = subprocess.run(base + [ip, _OID_SYS_DESCR],
                                capture_output=True, text=True, timeout=10)
            sys_descr = ' '.join(
                _snmp_clean(l.strip().strip('"'))
                for l in rd.stdout.strip().splitlines() if l.strip()
            ) if rd.returncode == 0 else ''
        except subprocess.TimeoutExpired:
            sys_descr = ''

        # ── sysObjectID — used to match vendor-specific OID tables ───────────
        sys_oid = _get(_OID_SYS_OBJECTID, timeout=8)

        # ── sysLocation — best-effort ─────────────────────────────────────────
        sys_location = _get(_OID_SYS_LOCATION, timeout=8)

        # ── Entity MIB — walk each column to find chassis entry at any index ──
        # Devices like Firepower/FTD and WLC don't always use index .1
        entity = {
            'sw_rev': _walk_first(_COL_ENT_SW_REV),
            'serial': _walk_first(_COL_ENT_SERIAL),
            'mfg':    _walk_first(_COL_ENT_MFG),
            'model':  _walk_first(_COL_ENT_MODEL),
        }

        # ── Vendor-specific OIDs — used when entity MIB is absent/empty ──────
        # Match on sysObjectID prefix; fetch individual scalar OIDs directly.
        vendor = {}
        if not all([entity['model'], entity['serial'], entity['sw_rev']]):
            # sysObjectID may come back as "iso.3.6.1…" — "iso." is "1." in OID notation
            sys_oid_norm = re.sub(r'^iso\.', '1.', sys_oid) if sys_oid else ''
            for oid_prefix, oid_map in _VENDOR_OIDS:
                if sys_oid_norm and sys_oid_norm.startswith(oid_prefix):
                    if not entity['model']  and 'model'  in oid_map:
                        vendor['model']  = _get(oid_map['model'])
                    if not entity['serial'] and 'serial' in oid_map:
                        vendor['serial'] = _get(oid_map['serial'])
                    if not entity['sw_rev'] and 'sw_rev' in oid_map:
                        vendor['sw_rev'] = _get(oid_map['sw_rev'])
                    break

        parsed = _parse_sys_descr(sys_descr)

        # ── Build field updates: entity MIB > vendor OIDs > sysDescr parse ───
        updates = {}

        if sys_name:
            updates['snmp_sysname'] = sys_name

        mfg = entity.get('mfg') or parsed.get('manufacturer', '')
        if mfg:
            updates['manufacturer'] = mfg

        model = entity.get('model') or vendor.get('model', '')
        if model:
            updates['model'] = model

        serial = entity.get('serial') or vendor.get('serial', '')
        if serial:
            updates['serial_number'] = serial

        ver = entity.get('sw_rev') or vendor.get('sw_rev') or parsed.get('version', '')
        if ver:
            updates['os_version'] = ver

        # Infer device_type only if not already set
        if not device.device_type:
            inferred = _infer_device_type(sys_descr)
            if inferred:
                updates['device_type'] = inferred

        # Location — only populate if currently blank
        if sys_location and not device.location:
            updates['location'] = sys_location

        # ── Scrub any SNMP null strings previously saved to the DB ───────────
        # If a field wasn't updated AND the DB value is a leftover error string,
        # clear it so it doesn't keep showing up.
        _clearable = ('manufacturer', 'model', 'serial_number', 'os_version', 'snmp_sysname')
        for field in _clearable:
            if field not in updates and _is_snmp_null(getattr(device, field, '')):
                updates[field] = ''

        # ── Save ──────────────────────────────────────────────────────────────
        if updates:
            for field, value in updates.items():
                setattr(device, field, value)
            device.save(update_fields=list(updates.keys()))

        # Response: use updated value, then fresh DB value — never a null string
        def _resp(field):
            v = updates.get(field)
            if v is not None:
                return v
            return _snmp_clean(getattr(device, field, '') or '')

        return {
            'success':        True,
            'profile':        profile.name,
            'fields_updated': {k: v for k, v in updates.items() if v},
            'error':          '',
            'snmp_sysname':   _resp('snmp_sysname'),
            'manufacturer':   _resp('manufacturer'),
            'model':          _resp('model'),
            'serial_number':  _resp('serial_number'),
            'os_version':     _resp('os_version'),
            'device_type':    _resp('device_type'),
        }

    return {
        'success': False,
        'profile': None,
        'fields_updated': {},
        'error': last_error or 'All SNMP profiles failed',
    }


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
# Bulk SNMP device update
# ---------------------------------------------------------------------------

@login_required
@require_POST
def network_snmp_update(request):
    """Poll a single device via its assigned SNMP profiles and update inventory fields."""
    body      = json.loads(request.body)
    device_id = body.get('device_id')
    device    = get_object_or_404(NetworkDevice, pk=device_id)
    result    = _snmp_update_device(device)
    return JsonResponse(result)


@login_required
@require_POST
def network_quick_add(request):
    """
    Create a NetworkDevice from a scan result.
    Uses the IP as both the device name and management IP.
    If a device with that name or management IP already exists, returns it instead.
    """
    body = json.loads(request.body)
    ip   = (body.get('ip') or '').strip()
    name = (body.get('name') or ip).strip() or ip

    if not ip:
        return JsonResponse({'error': 'IP address is required.'}, status=400)

    # Check for existing device by name or management IP
    existing = (NetworkDevice.objects.filter(name=name).first() or
                NetworkDevice.objects.filter(management_ip=ip).first() or
                NetworkDevice.objects.filter(primary_ip=ip).first())
    if existing:
        return JsonResponse({
            'exists':      True,
            'device_id':   existing.pk,
            'device_name': existing.name,
            'detail_url':  f'/inventory/network/{existing.pk}/',
        })

    device = NetworkDevice.objects.create(
        name          = name,
        management_ip = ip,
    )
    return JsonResponse({
        'created':     True,
        'device_id':   device.pk,
        'device_name': device.name,
        'detail_url':  f'/inventory/network/{device.pk}/',
    })


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
