from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    # Admin user management
    path('admin/users/', views.manage_users, name='manage_users'),
    path('admin/users/create/', views.create_user, name='create_user'),
    path('admin/users/<int:user_id>/edit/', views.edit_user, name='edit_user'),
    path('admin/users/<int:user_id>/reset-password/', views.reset_password, name='reset_password'),
    path('admin/users/<int:user_id>/toggle/', views.toggle_user, name='toggle_user'),
]
