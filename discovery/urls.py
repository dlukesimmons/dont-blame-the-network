from django.urls import path
from . import views

urlpatterns = [
    path('',                  views.discovery_list,    name='discovery_list'),
    path('new/',              views.discovery_new,     name='discovery_new'),
    path('<int:pk>/run/',     views.discovery_run,     name='discovery_run'),
    path('<int:pk>/stream/',  views.discovery_stream,  name='discovery_stream'),
    path('<int:pk>/',         views.discovery_detail,  name='discovery_detail'),
    path('<int:pk>/delete/',  views.discovery_delete,  name='discovery_delete'),
    path('compare/',          views.discovery_compare, name='discovery_compare'),
]
