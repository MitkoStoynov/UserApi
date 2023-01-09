import os
import re
import json
import copy
import socket
import logging
import jwt
import yaml
import time
import subprocess
from time import sleep
from random import uniform
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import warnings
from orm import User, Project, Database
warnings.filterwarnings("ignore")


def print_json(data, return_data=False):
    """
    :param data: Json config to be printed in formatted way.
    :param return_data: If True returns the formatted json as string otherwise prints on the screen.
    :return: print or return formatted json
    """
    try:
        if isinstance(data, str):
            json_data = json.loads(data)
        else:
            json_data = data
        str_data = json.dumps(json_data, indent=4, sort_keys=True)
        if return_data:
            return str_data
        print(str_data)
    except:
        if return_data:
            return data
        print(data)

def get_value(json_config, key, default=None):
    """
    Get a value from json config in dot separated format.
    Note that this search works with indexes if the json contains lists.
    For example: ucpe.config.interfaces['name'='data0'].metric
    This will search in the interfaces list for item with parameter name matching 'data0'
    and will continue with its elements.
    :param json_config: Json configuration
    :param key: The key to be found in the Json.
    :param default: The default value to be returned in case the key was not found.
    :return: Value of the key.
    """
    if not isinstance(json_config, dict):
        raise Exception("Invalid json format! {}".format(json_config))
    d = json_config
    keys = _xpath_dot_split(key)
    for d_key in keys[:-1]:
        if d_key.find('[') > -1 and d_key.find('[') > -1:
            # list index, find the key
            index = d_key[:d_key.find('[')]
            index_pair = d_key[d_key.find('[')+1:d_key.find(']')]
            index_key = index_pair[:index_pair.find('=')]
            index_value = index_pair[index_pair.find('=')+1:].replace('\'', '').replace('"', '')
            if index not in d:
                return default
            i = 0
            is_found = False
            for list_value in d[index]:
                if index_key in list_value and str(list_value[index_key]) == index_value:
                    d = d[index][i]
                    is_found = True
                    break
                i += 1
            if not is_found:
                return default
            continue
        if d_key in d:
            d = d[d_key]
            continue
        return default
    if (isinstance(d, dict) or isinstance(d, list)) and keys[-1] in d:
        return d[keys[-1]]
    return default


def _xpath_dot_split(key):
    """
    Internal function used for get_value
    """
    items = []
    parts = str(key).split('.')
    i = 0
    while i < len(parts):
        if parts[i].find('[') > -1 and parts[i][parts[i].find('['):].find(']') == -1:
            data = parts[i]
            while i < len(parts):
                i += 1
                data += '.' + parts[i]
                if parts[i].find(']') > -1:
                    items.append(data)
                    i += 1
                    break
            continue
        items.append(parts[i])
        i += 1
    return items


def get_manager_token(private_key_file, user, role=1, expire_hours=1, is_superuser=False):
    with open(private_key_file, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), None, backend=default_backend()
        )
    iss = datetime.utcnow()
    exp = iss + timedelta(hours=expire_hours)
    json_data = {"nbf": iss, "user": user, "role": role, "exp": exp, "is_super_user": 1 if is_superuser else 0}
    return jwt.encode(json_data, private_key, algorithm="RS256")


def decode_manager_token(public_key_file, token):
    with open(public_key_file, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )
    try:
        decoded = jwt.decode(token, key=public_key, algorithms=["RS256"])
        if not get_value(decoded, 'user') or get_value(decoded, 'role') is None:
            raise Exception('Invalid token!')
        user = get_value(decoded, 'user', '')
        if user.find('@') < 0:
            raise Exception('Invalid token!')
        decoded['username'] = user[:user.rfind('@')]
        decoded['project'] = user[user.rfind('@') + 1:]
        return decoded
    except Exception as ex:
        logger.error(ex)
        raise Exception('Invalid token!')