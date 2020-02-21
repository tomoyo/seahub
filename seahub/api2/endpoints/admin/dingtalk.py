# Copyright (c) 2012-2019 Seafile Ltd.

# encoding: utf-8

import logging
import requests

from django.core.cache import cache
from django.core.files.base import ContentFile

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error

from seahub.base.accounts import User
from seahub.utils.auth import gen_user_virtual_id
from seahub.auth.models import SocialAuthUser
from seahub.profile.models import Profile
from seahub.avatar.models import Avatar

from seahub.utils import normalize_cache_key
from seahub.dingtalk.settings import ENABLE_DINGTALK_DEPARTMENT, DINGTALK_DEPARTMENT_APP_KEY, \
        DINGTALK_DEPARTMENT_APP_SECRET, DINGTALK_DEPARTMENT_GET_ACCESS_TOKEN_URL, \
        DINGTALK_DEPARTMENT_GET_DEPARTMENT_URL, DINGTALK_DEPARTMENT_GET_DEPARTMENT_USER_LIST_URL

logger = logging.getLogger(__name__)


def get_dingtalk_access_token():

    cache_key = normalize_cache_key('DINGTALK_ACCESS_TOKEN')
    access_token = cache.get(cache_key, None)

    if not access_token:

        data = {
            'appkey': DINGTALK_DEPARTMENT_APP_KEY,
            'appsecret': DINGTALK_DEPARTMENT_APP_SECRET,
        }
        resp_json = requests.get(DINGTALK_DEPARTMENT_GET_ACCESS_TOKEN_URL,
                params=data).json()

        access_token = resp_json.get('access_token', '')
        if not access_token:
            logger.error('failed to get dingtalk access_token')
            logger.error(data)
            logger.error(DINGTALK_DEPARTMENT_GET_ACCESS_TOKEN_URL)
            logger.error(resp_json)
            return ''

        expires_in = resp_json.get('expires_in', 7200)
        cache.set(cache_key, access_token, expires_in)

    return access_token

def update_dingtalk_user_info(email, name, contact_email, avatar_url):

    # make sure the contact_email is unique
    if contact_email and Profile.objects.get_profile_by_contact_email(contact_email):
        logger.warning('contact email %s already exists' % contact_email)
        contact_email = ''

    profile_kwargs = {}
    if name:
        profile_kwargs['nickname'] = name
    if contact_email:
        profile_kwargs['contact_email'] = contact_email

    if profile_kwargs:
        try:
            Profile.objects.add_or_update(email, **profile_kwargs)
        except Exception as e:
            logger.error(e)

    try:
        image_name = 'dingtalk_avatar'
        image_file = requests.get(avatar_url).content
        avatar = Avatar.objects.filter(emailuser=email, primary=True).first()
        avatar = avatar or Avatar(emailuser=email, primary=True)
        avatar_file = ContentFile(image_file)
        avatar_file.name = image_name
        avatar.avatar = avatar_file
        avatar.save()
    except Exception as e:
        logger.error(e)

class AdminDingtalkDepartments(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)

    def get(self, request):

        if not ENABLE_DINGTALK_DEPARTMENT:
            error_msg = 'Feature is not enabled.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        if not request.user.admin_permissions.can_manage_user():
            return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')

        access_token = get_dingtalk_access_token()
        if not access_token:
            error_msg = '获取钉钉组织架构失败'
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        data = {
            'access_token': access_token,
        }
        resp_json = requests.get(DINGTALK_DEPARTMENT_GET_DEPARTMENT_URL, params=data).json()
        if not resp_json.get('department', ''):
            logger.error('failed to get dingtalk department')
            logger.error(data)
            logger.error(DINGTALK_DEPARTMENT_GET_DEPARTMENT_URL)
            logger.error(resp_json)
            error_msg = '获取企业微信组织架构失败'
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        return Response(resp_json)


class AdminDingtalkDepartmentMembers(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)

    def get(self, request, department_id):

        if not ENABLE_DINGTALK_DEPARTMENT:
            error_msg = 'Feature is not enabled.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        if not request.user.admin_permissions.can_manage_user():
            return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')

        access_token = get_dingtalk_access_token()
        if not access_token:
            error_msg = '获取钉钉组织架构失败'
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        data = {
            'access_token': access_token,
            'department_id': department_id,
            'offset': 0,
            'size': 100,
        }
        resp_json = requests.get(DINGTALK_DEPARTMENT_GET_DEPARTMENT_USER_LIST_URL, params=data).json()
        if not resp_json.get('userlist', ''):
            logger.error('failed to get dingtalk department user list')
            logger.error(data)
            logger.error(DINGTALK_DEPARTMENT_GET_DEPARTMENT_USER_LIST_URL)
            logger.error(resp_json)
            error_msg = '获取钉钉组织架构失败'
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        user_id_name_dict = {}
        auth_users = SocialAuthUser.objects.filter(provider='dingtalk')
        for user in auth_users:
            user_id_name_dict[user.unionid] = user.username

        for user in resp_json['userlist']:
            uid = user.get('unionid', '')
            user['contact_email'] = user.get('email', '')
            user['userid'] = uid

            # #  determine the user exists
            if uid in user_id_name_dict.keys():
                user['email'] = user_id_name_dict[uid]
            else:
                user['email'] = ''

        return Response(resp_json)


class AdminDingtalkUsersBatch(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def post(self, request):

        # parameter check
        user_list = request.data.get('userlist', [])
        if not user_list:
            error_msg = 'userlist invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # permission check
        if not ENABLE_DINGTALK_DEPARTMENT:
            error_msg = 'Feature is not enabled.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        if not request.user.admin_permissions.can_manage_user():
            return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')

        user_ids_in_db = []
        auth_users = SocialAuthUser.objects.filter(provider='dingtalk')
        for user in auth_users:
            user_ids_in_db.append(user.uid)

        success = []
        failed = []

        for user in user_list:

            user_id = user.get('userid')

            if user_id in user_ids_in_db:
                failed.append({
                    'userid': user_id,
                    'name': user.get('name'),
                    'error_msg': '用户已存在',
                })
                continue

            email = gen_user_virtual_id()
            try:
                User.objects.create_user(email)
                SocialAuthUser.objects.add(email, 'dingtalk', user_id)
                success.append({
                    'userid': user_id,
                    'name': user.get('name'),
                    'email': email,
                })
            except Exception as e:
                logger.error(e)
                failed.append({
                    'userid': user_id,
                    'name': user.get('name'),
                    'error_msg': '导入失败'
                })

            try:
                update_dingtalk_user_info(email, user.get('name'),
                        user.get('contact_email'), user.get('avatar'))
            except Exception as e:
                logger.error(e)

        return Response({'success': success, 'failed': failed})
