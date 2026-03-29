import io
import json
import re
import threading
import time
from queue import Empty, Queue
from concurrent.futures import ThreadPoolExecutor

from django.contrib.auth.decorators import login_required
from django.db import close_old_connections
from django.db.models import Count
from django.http import StreamingHttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

import paramiko

from credentials.models import SSHProfile
from inventory.models import NetworkDevice
from .models import DeviceDiscoveryResult, DiscoverySnapshot


# ── Manufacturer command profiles ──────────────────────────────────────────

MANUFACTURER_PROFILES = {
    'cisco': {
        'label': 'Cisco IOS/NX-OS',
        'pre':   ['terminal length 0'],
        'arp':   'show ip arp',
        'mac':   'show mac address-table',
    },
    'juniper': {
        'label': 'Juniper',
        'pre':   ['set cli screen-length 0'],
        'arp':   'show arp',
        'mac':   'show ethernet-switching table',
    },
    'aruba': {
        'label': 'Aruba',
        'pre':   ['no page'],
        'arp':   'show arp',
        'mac':   'show mac-address-table',
    },
    'hp': {
        'label': 'HP/Aruba',
        'pre':   ['no page'],
        'arp':   'show arp',
        'mac':   'show mac-address-table',
    },
    'extreme': {
        'label': 'Extreme Networks',
        'pre':   ['disable clipaging'],
        'arp':   'show arp',
        'mac':   'show fdb',
    },
    'fortinet': {
        'label': 'Fortinet',
        'pre':   [],
        'arp':   'get system arp',
        'mac':   'diagnose netlink brctl name host bridge',
    },
}
_DEFAULT_MFR = MANUFACTURER_PROFILES['cisco']


def _get_mfr_profile(manufacturer):
    m = (manufacturer or '').lower()
    for key, prof in MANUFACTURER_PROFILES.items():
        if key in m:
            return prof
    return _DEFAULT_MFR


# ── SSH helpers ─────────────────────────────────────────────────────────────

def _recv_until_prompt(shell, timeout=30):
    """Read from shell until a CLI prompt character is detected."""
    buf = b''
    deadline = time.time() + timeout
    while time.time() < deadline:
        if shell.recv_ready():
            buf += shell.recv(8192)
            decoded = buf.decode('utf-8', errors='replace')
            if re.search(r'[#>]\s*$', decoded.rstrip()):
                break
        else:
            time.sleep(0.05)
    return buf.decode('utf-8', errors='replace')


def _run_device_commands(profile, ip, pre_commands, commands):
    """
    Open an SSH shell, run pre_commands (discarding output), then run
    each command and capture its output. Returns {command: output_str}.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    outputs = {}
    try:
        kwargs = dict(
            hostname=ip,
            port=profile.port,
            username=profile.username,
            timeout=30,
            banner_timeout=30,
            look_for_keys=False,
            allow_agent=False,
        )
        if profile.auth_method == SSHProfile.METHOD_KEY:
            kwargs['pkey'] = paramiko.RSAKey.from_private_key(
                io.StringIO(profile.private_key)
            )
        else:
            kwargs['password'] = profile.password

        client.connect(**kwargs)
        shell = client.invoke_shell(width=220, height=200)
        shell.settimeout(30)
        _recv_until_prompt(shell)  # clear login banner

        for cmd in pre_commands:
            shell.send(cmd + '\n')
            _recv_until_prompt(shell)

        for cmd in commands:
            shell.send(cmd + '\n')
            raw = _recv_until_prompt(shell)
            # Strip echoed command line
            lines = raw.splitlines()
            out_lines = []
            skipped_echo = False
            for line in lines:
                if not skipped_echo and cmd.strip() in line:
                    skipped_echo = True
                    continue
                out_lines.append(line)
            # Strip trailing prompt line
            if out_lines and re.search(r'[#>]\s*$', out_lines[-1]):
                out_lines = out_lines[:-1]
            outputs[cmd] = '\n'.join(out_lines)
    finally:
        try:
            client.close()
        except Exception:
            pass
    return outputs


# ── Output parsers ──────────────────────────────────────────────────────────

def _parse_cisco_arp(text):
    """Parse 'show ip arp' → list of {ip, mac, interface}."""
    entries = []
    for line in (text or '').splitlines():
        m = re.match(
            r'\s*Internet\s+(\S+)\s+\S+\s+'
            r'([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})'
            r'\s+\S+\s+(\S+)',
            line,
        )
        if m:
            entries.append({
                'ip':        m.group(1),
                'mac':       m.group(2).lower(),
                'interface': m.group(3),
            })
    return entries


def _parse_cisco_mac_table(text):
    """Parse 'show mac address-table' → list of {vlan, mac, type, port}."""
    entries = []
    for line in (text or '').splitlines():
        m = re.match(
            r'\s*(\d+)\s+'
            r'([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})'
            r'\s+(\S+)\s+(\S+)',
            line,
        )
        if m:
            entries.append({
                'vlan': m.group(1),
                'mac':  m.group(2).lower(),
                'type': m.group(3),
                'port': m.group(4),
            })
    return entries


def _parse_result(result):
    """Parse a DeviceDiscoveryResult's outputs into structured tables."""
    if result.status != DeviceDiscoveryResult.STATUS_SUCCESS:
        return [], []
    return (
        _parse_cisco_arp(result.arp_output),
        _parse_cisco_mac_table(result.mac_output),
    )


# ── SSE streaming worker ────────────────────────────────────────────────────

def _process_device(device, snapshot_id, queue):
    """Run SSH discovery on one device; put result dict on queue."""
    close_old_connections()
    event = {'type': 'device_done', 'device_id': device.pk, 'device_name': device.name}
    try:
        result = DeviceDiscoveryResult.objects.get(
            snapshot_id=snapshot_id, device=device
        )
        ip = str(device.management_ip or device.primary_ip or '').strip()
        if not ip:
            result.status = DeviceDiscoveryResult.STATUS_NO_IP
            result.save()
            queue.put({**event, 'status': 'no_ip', 'error': ''})
            return

        profile = device.ssh_profiles.first()
        if not profile:
            result.status = DeviceDiscoveryResult.STATUS_NO_SSH
            result.save()
            queue.put({**event, 'status': 'no_ssh', 'error': ''})
            return

        mfr = _get_mfr_profile(device.manufacturer)
        try:
            outputs = _run_device_commands(
                profile, ip, mfr['pre'], [mfr['arp'], mfr['mac']]
            )
            result.arp_output = outputs.get(mfr['arp'], '')
            result.mac_output = outputs.get(mfr['mac'], '')
            result.status = DeviceDiscoveryResult.STATUS_SUCCESS
            result.error  = ''
        except Exception as exc:
            result.status = DeviceDiscoveryResult.STATUS_FAILED
            result.error  = str(exc)

        result.collected_at = timezone.now()
        result.save()
        queue.put({**event, 'status': result.status, 'error': result.error})

    except Exception as exc:
        queue.put({**event, 'status': 'failed', 'error': str(exc)})


def _discovery_stream_generator(snapshot_id):
    """Generator that yields SSE events for the discovery run."""
    snapshot = DiscoverySnapshot.objects.get(pk=snapshot_id)
    snapshot.status = DiscoverySnapshot.STATUS_RUNNING
    snapshot.save()

    qs = NetworkDevice.objects.prefetch_related('ssh_profiles')
    if snapshot.site:
        qs = qs.filter(location=snapshot.site)
    devices = list(qs)

    snapshot.device_count = len(devices)
    snapshot.save()

    yield f"data: {json.dumps({'type': 'start', 'total': len(devices)})}\n\n"

    if not devices:
        snapshot.status = DiscoverySnapshot.STATUS_COMPLETE
        snapshot.save()
        yield f"data: {json.dumps({'type': 'complete', 'snapshot_id': snapshot_id})}\n\n"
        return

    queue     = Queue()
    done_evt  = threading.Event()
    completed = [0]

    def _run_all():
        with ThreadPoolExecutor(max_workers=10) as exe:
            futs = [exe.submit(_process_device, d, snapshot_id, queue) for d in devices]
            for f in futs:
                try:
                    f.result()
                except Exception:
                    pass
        done_evt.set()

    threading.Thread(target=_run_all, daemon=True).start()

    while not done_evt.is_set() or not queue.empty():
        try:
            item = queue.get(timeout=0.5)
            completed[0] += 1
            item['progress'] = completed[0]
            item['total']    = len(devices)
            yield f"data: {json.dumps(item)}\n\n"
        except Empty:
            yield ': ping\n\n'

    snapshot.status        = DiscoverySnapshot.STATUS_COMPLETE
    snapshot.success_count = snapshot.results.filter(
        status=DeviceDiscoveryResult.STATUS_SUCCESS
    ).count()
    snapshot.save()
    yield f"data: {json.dumps({'type': 'complete', 'snapshot_id': snapshot_id})}\n\n"


# ── Comparison helper ───────────────────────────────────────────────────────

def _build_comparison(snap_a, snap_b):
    ra_map = {r.device_id: r for r in snap_a.results.select_related('device')}
    rb_map = {r.device_id: r for r in snap_b.results.select_related('device')}
    all_ids = set(ra_map) | set(rb_map)

    devices = []
    total_new = total_removed = 0

    for dev_id in all_ids:
        ra = ra_map.get(dev_id)
        rb = rb_map.get(dev_id)
        device = (ra or rb).device

        arp_a = _parse_cisco_arp(ra.arp_output) if ra and ra.status == 'success' else []
        arp_b = _parse_cisco_arp(rb.arp_output) if rb and rb.status == 'success' else []
        mac_a = _parse_cisco_mac_table(ra.mac_output) if ra and ra.status == 'success' else []
        mac_b = _parse_cisco_mac_table(rb.mac_output) if rb and rb.status == 'success' else []

        marp_a = {e['mac']: e for e in arp_a}
        marp_b = {e['mac']: e for e in arp_b}
        mmac_a = {e['mac']: e for e in mac_a}
        mmac_b = {e['mac']: e for e in mac_b}

        arp_diff = (
            [{'state': 'removed', **e} for k, e in sorted(marp_a.items()) if k not in marp_b] +
            [{'state': 'same',    **e} for k, e in sorted(marp_a.items()) if k in marp_b]     +
            [{'state': 'added',   **e} for k, e in sorted(marp_b.items()) if k not in marp_a]
        )
        mac_diff = (
            [{'state': 'removed', **e} for k, e in sorted(mmac_a.items()) if k not in mmac_b] +
            [{'state': 'same',    **e} for k, e in sorted(mmac_a.items()) if k in mmac_b]     +
            [{'state': 'added',   **e} for k, e in sorted(mmac_b.items()) if k not in mmac_a]
        )

        new_c = sum(1 for e in arp_diff + mac_diff if e['state'] == 'added')
        rem_c = sum(1 for e in arp_diff + mac_diff if e['state'] == 'removed')
        total_new      += new_c
        total_removed  += rem_c

        devices.append({
            'device':        device,
            'only_in_a':     ra is not None and rb is None,
            'only_in_b':     ra is None and rb is not None,
            'arp_diff':      arp_diff,
            'mac_diff':      mac_diff,
            'new_count':     new_c,
            'removed_count': rem_c,
        })

    devices.sort(key=lambda d: d['device'].name)
    return {
        'snap_a':        snap_a,
        'snap_b':        snap_b,
        'devices':       devices,
        'total_new':     total_new,
        'total_removed': total_removed,
    }


# ── Views ────────────────────────────────────────────────────────────────────

@login_required
def discovery_list(request):
    snapshots = DiscoverySnapshot.objects.select_related('created_by').all()
    complete_snapshots = snapshots.filter(status=DiscoverySnapshot.STATUS_COMPLETE)
    return render(request, 'discovery/discovery_list.html', {
        'snapshots':          snapshots,
        'complete_snapshots': complete_snapshots,
    })


@login_required
def discovery_new(request):
    # Distinct locations with device counts
    site_data = (
        NetworkDevice.objects
        .exclude(location='')
        .values('location')
        .annotate(n=Count('id'))
        .order_by('location')
    )
    all_count = NetworkDevice.objects.count()

    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        site = request.POST.get('site', '').strip()
        if not name:
            label = site if site else 'All Sites'
            name  = f"Discovery — {label} — {timezone.now().strftime('%Y-%m-%d %H:%M')}"

        snapshot = DiscoverySnapshot.objects.create(
            name=name, site=site,
            status=DiscoverySnapshot.STATUS_PENDING,
            created_by=request.user,
        )
        # Pre-create result rows
        qs = NetworkDevice.objects.all() if not site else NetworkDevice.objects.filter(location=site)
        DeviceDiscoveryResult.objects.bulk_create([
            DeviceDiscoveryResult(snapshot=snapshot, device=d) for d in qs
        ])
        return redirect('discovery_run', pk=snapshot.pk)

    return render(request, 'discovery/discovery_new.html', {
        'site_data':  site_data,
        'all_count':  all_count,
    })


@login_required
def discovery_run(request, pk):
    snapshot = get_object_or_404(DiscoverySnapshot, pk=pk)
    results  = snapshot.results.select_related('device').all()
    return render(request, 'discovery/discovery_run.html', {
        'snapshot': snapshot,
        'results':  results,
    })


@login_required
def discovery_stream(request, pk):
    snapshot = get_object_or_404(DiscoverySnapshot, pk=pk)
    resp = StreamingHttpResponse(
        _discovery_stream_generator(snapshot.pk),
        content_type='text/event-stream',
    )
    resp['Cache-Control']      = 'no-cache'
    resp['X-Accel-Buffering']  = 'no'
    return resp


@login_required
def discovery_detail(request, pk):
    snapshot = get_object_or_404(DiscoverySnapshot, pk=pk)
    results  = snapshot.results.select_related('device').all()

    parsed = []
    for r in results:
        arp_entries, mac_entries = _parse_result(r)
        parsed.append({
            'result':      r,
            'arp_entries': arp_entries,
            'mac_entries': mac_entries,
        })

    counts = {s: 0 for s in ['success', 'failed', 'no_ssh', 'no_ip', 'pending']}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    return render(request, 'discovery/discovery_detail.html', {
        'snapshot': snapshot,
        'parsed':   parsed,
        'counts':   counts,
    })


@login_required
def discovery_compare(request):
    complete = DiscoverySnapshot.objects.filter(
        status=DiscoverySnapshot.STATUS_COMPLETE
    ).order_by('-created_at')

    a_id = request.GET.get('a')
    b_id = request.GET.get('b')
    comparison = None

    if a_id and b_id and a_id != b_id:
        snap_a = get_object_or_404(DiscoverySnapshot, pk=a_id)
        snap_b = get_object_or_404(DiscoverySnapshot, pk=b_id)
        comparison = _build_comparison(snap_a, snap_b)

    return render(request, 'discovery/discovery_compare.html', {
        'complete':    complete,
        'snap_a_id':   a_id,
        'snap_b_id':   b_id,
        'comparison':  comparison,
    })


@login_required
@require_POST
def discovery_delete(request, pk):
    snapshot = get_object_or_404(DiscoverySnapshot, pk=pk)
    snapshot.delete()
    return redirect('discovery_list')
