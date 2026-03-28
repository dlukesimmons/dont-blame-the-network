from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from .forms import LoginForm, UserCreateForm, UserEditForm, PasswordResetForm
from .models import User


def is_admin(user):
    return user.is_staff or user.is_superuser


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    form = LoginForm(request, data=request.POST or None)
    if request.method == 'POST':
        if form.is_valid():
            login(request, form.get_user())
            return redirect('dashboard')
        messages.error(request, 'Invalid username or password.')

    return render(request, 'accounts/login.html', {'form': form})


def logout_view(request):
    logout(request)
    return redirect('login')


@login_required
def dashboard(request):
    context = {}
    if request.user.is_admin:
        context['user_count'] = User.objects.count()
        context['active_count'] = User.objects.filter(is_active=True).count()
        context['admin_count'] = User.objects.filter(is_staff=True).count()
    return render(request, 'accounts/dashboard.html', context)


@login_required
@user_passes_test(is_admin)
def manage_users(request):
    users = User.objects.all().order_by('username')
    return render(request, 'accounts/manage_users.html', {'users': users})


@login_required
@user_passes_test(is_admin)
def create_user(request):
    form = UserCreateForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user = form.save()
        messages.success(request, f'User "{user.username}" created successfully.')
        return redirect('manage_users')
    return render(request, 'accounts/user_form.html', {
        'form': form,
        'title': 'Create User',
        'action': 'Create User',
    })


@login_required
@user_passes_test(is_admin)
def edit_user(request, user_id):
    target = get_object_or_404(User, pk=user_id)
    if target.is_superuser and not request.user.is_superuser:
        messages.error(request, 'You cannot edit a superuser account.')
        return redirect('manage_users')

    form = UserEditForm(request.POST or None, instance=target)
    if request.method == 'POST' and form.is_valid():
        form.save()
        messages.success(request, f'User "{target.username}" updated successfully.')
        return redirect('manage_users')
    return render(request, 'accounts/user_form.html', {
        'form': form,
        'title': f'Edit User: {target.username}',
        'action': 'Save Changes',
        'target_user': target,
    })


@login_required
@user_passes_test(is_admin)
def reset_password(request, user_id):
    target = get_object_or_404(User, pk=user_id)
    if target.is_superuser and not request.user.is_superuser:
        messages.error(request, 'You cannot reset a superuser password.')
        return redirect('manage_users')

    form = PasswordResetForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        target.set_password(form.cleaned_data['new_password'])
        target.save()
        messages.success(request, f'Password for "{target.username}" has been reset.')
        return redirect('manage_users')
    return render(request, 'accounts/user_form.html', {
        'form': form,
        'title': f'Reset Password: {target.username}',
        'action': 'Reset Password',
        'target_user': target,
    })


@login_required
@user_passes_test(is_admin)
def toggle_user(request, user_id):
    target = get_object_or_404(User, pk=user_id)
    if target == request.user:
        messages.error(request, 'You cannot deactivate your own account.')
    elif target.is_superuser and not request.user.is_superuser:
        messages.error(request, 'You cannot deactivate a superuser account.')
    else:
        target.is_active = not target.is_active
        target.save()
        action = 'activated' if target.is_active else 'deactivated'
        messages.success(request, f'User "{target.username}" has been {action}.')
    return redirect('manage_users')
