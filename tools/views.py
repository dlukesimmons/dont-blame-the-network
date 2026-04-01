import json

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, StreamingHttpResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.http import require_POST

from credentials.models import SNMPProfile
from .scanner import validate_network, validate_networks, run_icmp_scan, run_tcp_scan, run_snmp_scan_stream


@login_required
def icmp_scan(request):
    return render(request, 'tools/icmp_scan.html')


@login_required
@require_POST
def icmp_scan_run(request):
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({'error': 'Invalid request.'}, status=400)

    raw_network      = body.get('network', '').strip()
    resolve_dns      = bool(body.get('resolve_dns', False))
    resolve_netbios  = bool(body.get('resolve_netbios', False))

    if not raw_network:
        return JsonResponse({'error': 'Network address is required.'}, status=400)

    try:
        network = validate_network(raw_network)
    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)

    result = run_icmp_scan(network, resolve_dns=resolve_dns, resolve_netbios=resolve_netbios)

    return JsonResponse({
        'network':     network,
        'hosts':       result['hosts'],
        'up_count':    result['up_count'],
        'total_count': result['total_count'],
        'error':       result['error'],
    })


@login_required
@require_POST
def tcp_scan_run(request):
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({'error': 'Invalid request.'}, status=400)

    raw_network     = body.get('network', '').strip()
    ports           = body.get('ports', '').strip() or '22,23,80,443,8080,8443'
    resolve_dns     = bool(body.get('resolve_dns', False))
    resolve_netbios = bool(body.get('resolve_netbios', False))

    if not raw_network:
        return JsonResponse({'error': 'Network address is required.'}, status=400)

    try:
        network = validate_network(raw_network)
    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)

    result = run_tcp_scan(network, ports=ports, resolve_dns=resolve_dns,
                          resolve_netbios=resolve_netbios)
    return JsonResponse({
        'network':     network,
        'hosts':       result['hosts'],
        'up_count':    result['up_count'],
        'total_count': result['total_count'],
        'error':       result['error'],
    })


@login_required
def snmp_scan(request):
    return render(request, 'tools/snmp_scan.html', {
        'snmp_profiles': SNMPProfile.objects.all(),
    })


@login_required
@require_POST
def snmp_scan_run(request):
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({'error': 'Invalid request.'}, status=400)

    raw_network = body.get('network', '').strip()
    profile_id  = body.get('profile_id')

    if not raw_network:
        return JsonResponse({'error': 'Network address is required.'}, status=400)
    if not profile_id:
        return JsonResponse({'error': 'SNMP profile is required.'}, status=400)

    try:
        network = validate_network(raw_network)
    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)

    profile = get_object_or_404(SNMPProfile, pk=profile_id)

    def event_stream():
        up_count = 0
        total    = 0
        for result in run_snmp_scan_stream(network, profile):
            total = result.get('total', 0)
            if result.get('status') == 'up':
                up_count += 1
            result['up_count'] = up_count
            yield f"data: {json.dumps({**result, 'type': 'host'})}\n\n"
        yield f"data: {json.dumps({'type': 'done', 'up_count': up_count, 'total': total})}\n\n"

    response = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
    response['X-Accel-Buffering'] = 'no'
    response['Cache-Control']     = 'no-cache'
    return response


@login_required
def bulk_scan(request):
    return render(request, 'tools/bulk_scan.html')


@login_required
@require_POST
def bulk_scan_stream(request):
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({'error': 'Invalid request.'}, status=400)

    raw_networks    = body.get('networks', '').strip()
    resolve_dns     = bool(body.get('resolve_dns', False))
    resolve_netbios = bool(body.get('resolve_netbios', False))

    if not raw_networks:
        return JsonResponse({'error': 'No networks provided.'}, status=400)

    try:
        networks = validate_networks(raw_networks)
    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)

    def event_stream():
        for i, network in enumerate(networks):
            # Signal scan start for this network
            yield 'data: ' + json.dumps({
                'type':    'start',
                'network': network,
                'index':   i,
                'total':   len(networks),
            }) + '\n\n'

            result = run_icmp_scan(network, resolve_dns=resolve_dns, resolve_netbios=resolve_netbios)

            yield 'data: ' + json.dumps({
                'type':        'result',
                'network':     network,
                'index':       i,
                'total':       len(networks),
                'hosts':       result['hosts'],
                'up_count':    result['up_count'],
                'total_count': result['total_count'],
                'error':       result['error'],
            }) + '\n\n'

        yield 'data: ' + json.dumps({'type': 'done'}) + '\n\n'

    response = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
    response['X-Accel-Buffering'] = 'no'
    response['Cache-Control']     = 'no-cache'
    return response
