import json

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, StreamingHttpResponse
from django.shortcuts import render
from django.views.decorators.http import require_POST

from .scanner import validate_network, validate_networks, run_icmp_scan


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
