from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect


def root_redirect(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return redirect('login')


urlpatterns = [
    path('django-admin/',    admin.site.urls),
    path('accounts/',        include('accounts.urls')),
    path('tools/',           include('tools.urls')),
    path('inventory/',       include('inventory.urls')),
    path('credentials/',     include('credentials.urls')),
    path('discovery/',       include('discovery.urls')),
    path('',                 root_redirect, name='root'),
]
