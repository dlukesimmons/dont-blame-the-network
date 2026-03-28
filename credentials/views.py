from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_POST

from .models import SNMPProfile, SSHProfile, HTTPSProfile
from .forms import SNMPProfileForm, SSHProfileForm, HTTPSProfileForm


# ---------------------------------------------------------------------------
# SNMP
# ---------------------------------------------------------------------------

@login_required
def snmp_list(request):
    q = request.GET.get('q', '').strip()
    profiles = SNMPProfile.objects.all()
    if q:
        profiles = profiles.filter(name__icontains=q)
    return render(request, 'credentials/snmp_list.html', {'profiles': profiles, 'q': q})


@login_required
def snmp_add(request):
    form = SNMPProfileForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        profile = form.save()
        messages.success(request, f'SNMP profile "{profile.name}" created.')
        return redirect('snmp_list')
    return render(request, 'credentials/snmp_form.html', {
        'form': form, 'title': 'Add SNMP Profile', 'action': 'Create Profile',
        'cancel_url': 'snmp_list',
    })


@login_required
def snmp_edit(request, pk):
    profile = get_object_or_404(SNMPProfile, pk=pk)
    form = SNMPProfileForm(request.POST or None, instance=profile)
    if request.method == 'POST' and form.is_valid():
        form.save()
        messages.success(request, f'SNMP profile "{profile.name}" updated.')
        return redirect('snmp_list')
    return render(request, 'credentials/snmp_form.html', {
        'form': form, 'title': f'Edit: {profile.name}', 'action': 'Save Changes',
        'cancel_url': 'snmp_list', 'profile': profile,
    })


@login_required
@require_POST
def snmp_delete(request, pk):
    profile = get_object_or_404(SNMPProfile, pk=pk)
    name = profile.name
    profile.delete()
    messages.success(request, f'SNMP profile "{name}" deleted.')
    return redirect('snmp_list')


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

@login_required
def ssh_list(request):
    q = request.GET.get('q', '').strip()
    profiles = SSHProfile.objects.all()
    if q:
        profiles = profiles.filter(name__icontains=q)
    return render(request, 'credentials/ssh_list.html', {'profiles': profiles, 'q': q})


@login_required
def ssh_add(request):
    form = SSHProfileForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        profile = form.save()
        messages.success(request, f'SSH profile "{profile.name}" created.')
        return redirect('ssh_list')
    return render(request, 'credentials/ssh_form.html', {
        'form': form, 'title': 'Add SSH Profile', 'action': 'Create Profile',
        'cancel_url': 'ssh_list',
    })


@login_required
def ssh_edit(request, pk):
    profile = get_object_or_404(SSHProfile, pk=pk)
    form = SSHProfileForm(request.POST or None, instance=profile)
    if request.method == 'POST' and form.is_valid():
        form.save()
        messages.success(request, f'SSH profile "{profile.name}" updated.')
        return redirect('ssh_list')
    return render(request, 'credentials/ssh_form.html', {
        'form': form, 'title': f'Edit: {profile.name}', 'action': 'Save Changes',
        'cancel_url': 'ssh_list', 'profile': profile,
    })


@login_required
@require_POST
def ssh_delete(request, pk):
    profile = get_object_or_404(SSHProfile, pk=pk)
    name = profile.name
    profile.delete()
    messages.success(request, f'SSH profile "{name}" deleted.')
    return redirect('ssh_list')


# ---------------------------------------------------------------------------
# HTTPS
# ---------------------------------------------------------------------------

@login_required
def https_list(request):
    q = request.GET.get('q', '').strip()
    profiles = HTTPSProfile.objects.all()
    if q:
        profiles = profiles.filter(name__icontains=q)
    return render(request, 'credentials/https_list.html', {'profiles': profiles, 'q': q})


@login_required
def https_add(request):
    form = HTTPSProfileForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        profile = form.save()
        messages.success(request, f'HTTPS profile "{profile.name}" created.')
        return redirect('https_list')
    return render(request, 'credentials/https_form.html', {
        'form': form, 'title': 'Add HTTPS Profile', 'action': 'Create Profile',
        'cancel_url': 'https_list',
    })


@login_required
def https_edit(request, pk):
    profile = get_object_or_404(HTTPSProfile, pk=pk)
    form = HTTPSProfileForm(request.POST or None, instance=profile)
    if request.method == 'POST' and form.is_valid():
        form.save()
        messages.success(request, f'HTTPS profile "{profile.name}" updated.')
        return redirect('https_list')
    return render(request, 'credentials/https_form.html', {
        'form': form, 'title': f'Edit: {profile.name}', 'action': 'Save Changes',
        'cancel_url': 'https_list', 'profile': profile,
    })


@login_required
@require_POST
def https_delete(request, pk):
    profile = get_object_or_404(HTTPSProfile, pk=pk)
    name = profile.name
    profile.delete()
    messages.success(request, f'HTTPS profile "{name}" deleted.')
    return redirect('https_list')
