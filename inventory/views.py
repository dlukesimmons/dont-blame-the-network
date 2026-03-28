from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_POST

from .models import NetworkDevice, Server
from .forms import NetworkDeviceForm, ServerForm


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
