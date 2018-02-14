#coding = utf-8
from django.conf.urls import url

from .import views



urlpatterns = [
    url(r'^input/$', views.input),     #注意  /
    url(r'^run/$',views.scan),
    ]