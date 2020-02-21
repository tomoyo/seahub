# -*- coding: utf-8 -*-

import uuid
import json
import time
import hmac
import base64
import urllib
import logging
import requests
from hashlib import sha256

from django.http import HttpResponseRedirect
from django.utils.translation import ugettext as _

from seahub.api2.utils import get_api_token
from seahub import auth
from seahub.profile.models import Profile
from seahub.utils import render_error
from seahub.utils.auth import gen_user_virtual_id
from seahub.base.accounts import User
from seahub.auth.models import SocialAuthUser

from seahub.dingtalk.settings import ENABLE_DINGTALK_QR_CONNECT, \
        DINGTALK_QR_CONNECT_APP_ID, DINGTALK_QR_CONNECT_APP_SECRET, \
        DINGTALK_QR_CONNECT_AUTHORIZATION_URL, DINGTALK_QR_CONNECT_REDIRECT_URL, \
        DINGTALK_QR_CONNECT_USER_INFO_URL, DINGTALK_QR_CONNECT_RESPONSE_TYPE, \
        DINGTALK_QR_CONNECT_SCOPE

logger = logging.getLogger(__name__)

def dingtalk_login(request):

    if not ENABLE_DINGTALK_QR_CONNECT:
        return render_error(request, _('Error, please contact administrator.'))

    state = str(uuid.uuid4())
    url = DINGTALK_QR_CONNECT_AUTHORIZATION_URL + '?appid=%s&response_type=%s&scope=%s&state=%s&redirect_uri=%s' \
            % (DINGTALK_QR_CONNECT_APP_ID, DINGTALK_QR_CONNECT_RESPONSE_TYPE, \
            DINGTALK_QR_CONNECT_SCOPE, state, DINGTALK_QR_CONNECT_REDIRECT_URL)

    request.session['dingtalk_state'] = state
    request.session['oauth_redirect'] = request.GET.get(
        auth.REDIRECT_FIELD_NAME, '/')

    return HttpResponseRedirect(url)

def dingtalk_callback(request):

    if not ENABLE_DINGTALK_QR_CONNECT:
        return render_error(request, _('Error, please contact administrator.'))

    timestamp = str(int(time.time()*1000)).encode('utf-8')
    appsecret = DINGTALK_QR_CONNECT_APP_SECRET.encode('utf-8')
    signature = base64.b64encode(hmac.new(appsecret, timestamp, digestmod=sha256).digest())
    parameters = {
        'accessKey': DINGTALK_QR_CONNECT_APP_ID,
        'timestamp': timestamp,
        'signature': signature,
    }

    code = request.GET.get('code')
    data = {"tmp_auth_code": code}

    full_user_info_url = DINGTALK_QR_CONNECT_USER_INFO_URL + '?' + urllib.parse.urlencode(parameters)
    user_info_resp = requests.post(full_user_info_url, data=json.dumps(data))
    user_info = user_info_resp.json()['user_info']

    # seahub authenticate user
    if 'unionid' not in user_info:
        logger.error('Required user info not found.')
        logger.error(user_info)
        return render_error(request, _('Error, please contact administrator.'))

    auth_user = SocialAuthUser.objects.get_by_provider_and_uid('dingtalk', user_info['unionid'])
    if auth_user:
        email = auth_user.username
    else:
        email = gen_user_virtual_id()
        SocialAuthUser.objects.add(email, 'dingtalk', user_info['unionid'])

    try:
        user = auth.authenticate(remote_user=email)
    except User.DoesNotExist:
        user = None

    if not user or not user.is_active:
        logger.error('User %s not found or inactive.' % email)
        # a page for authenticate user failed
        return render_error(request, _('User %s not found.') % email)

    # User is valid.  Set request.user and persist user in the session
    # by logging the user in.
    request.user = user
    auth.login(request, user)

    # update user's profile
    name = user_info['nick'] if 'nick' in user_info else ''
    if name:

        profile = Profile.objects.get_profile_by_user(email)
        if not profile:
            profile = Profile(user=email)

        profile.nickname = name.strip()
        profile.save()

    # generate auth token for Seafile client
    api_token = get_api_token(request)

    # redirect user to home page
    response = HttpResponseRedirect(request.session['oauth_redirect'])
    response.set_cookie('seahub_auth', email + '@' + api_token.key)
    return response
