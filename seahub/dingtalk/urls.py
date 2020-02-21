# Copyright (c) 2012-2016 Seafile Ltd.

from django.conf.urls import url
from seahub.dingtalk.views import dingtalk_login, dingtalk_callback

urlpatterns = [
    url(r'login/$', dingtalk_login, name='dingtalk_login'),
    url(r'callback/$', dingtalk_callback, name='dingtalk_callback'),
]
