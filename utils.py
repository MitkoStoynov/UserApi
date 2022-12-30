import os
import re
import json
import copy
import socket
import logging
import jwt
import redis
import yaml
import time
import subprocess
from time import sleep
from random import uniform
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import warnings
warnings.filterwarnings("ignore")

# Logging configuration
log_format = '%(asctime)s [%(levelname)-5.5s] %(message)s'
logger = logging.getLogger(__name__)
logFormatter = logging.Formatter('%(asctime)s [%(levelname)-5.5s]  %(message)s')


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


def set_value(json_config, key, value, create_missing=True, raise_exception=True):
    """
    Set a value in complex json config using dot separated keys. For more information look ata get_value.
    :param json_config: Json to be used as basis.
    :param key: Key to be set.
    :param value: Value to be set.
    :param create_missing: By default create the missing json structure in order to srt the value
    :param raise_exception: Raise exception by default.
    :return: Return the updated json with set value.
    """
    str_data = "locals()['json_config']"
    keys = _xpath_dot_split(key)
    for key in keys[:-1]:
        if key.find('[') > -1 and key.find(']') > -1 and key.find('=') > -1:
            # list index, find the key
            index = key[:key.find('[')]
            index_pair = key[key.find('[')+1:key.find(']')]
            index_key = index_pair[:index_pair.find('=')]
            index_value = index_pair[index_pair.find('=')+1:].replace('\'', '').replace('"', '')
            i = 0
            is_found = False
            if index in eval(str_data):
                for list_value in eval("{}['{}']".format(str_data, index)):
                    if isinstance(list_value, dict) and index_key in list_value and str(list_value[index_key]) == index_value:
                        is_found = True
                        str_data = "%s['%s'][%d]" % (str_data, index, i)
                        break
                    if list_value == index_key and eval("{}['{}']['{}']".format(str_data, index, index_key)) == index_value:
                        is_found = True
                        str_data = "%s['%s']" % (str_data, index)
                        break
                    i += 1
            if not is_found:
                if not create_missing:
                    if raise_exception:
                        raise Exception('Missing element {}'.format(key))
                else:
                    # add to list
                    if index not in eval(str_data):
                        exec("%s['%s'] = []" % (str_data, index))
                    exec("%s['%s'].append({index_key: index_value})" % (str_data, index))
                    str_data = "%s['%s'][%d]" % (str_data, index, len(eval("{}['{}']".format(str_data, index)))-1)
            continue
        if key in eval(str_data):
            str_data = "%s['%s']" % (str_data, key)
            continue
        if not create_missing:
            if raise_exception:
                raise Exception('Missing element {}'.format(key))
        else:
            exec("%s['%s'] = {}" % (str_data, key))
            str_data = "{}['{}']".format(str_data, key)
    if keys[-1] in eval(str_data):
        if create_missing:
            exec("{}['{}'] = value".format(str_data, keys[-1]))
    else:
        if not create_missing:
            if raise_exception:
                raise Exception('Missing element {}'.format(keys[-1]))
        else:
            exec("{}['{}'] = value".format(str_data, keys[-1]))
    return json_config


def get_indexed_list(data_list, key):
    """
    Get the list of dictionaries as dictionary indexed by it's key name.
    """
    data_dict = {}
    for val in data_list:
        if key in val:
            data_dict[val[key]] = val
    return data_dict


def get_indexed_config(config_data):
    indexed = copy.deepcopy(config_data)
    index_list = [
        {"key": "ietf-netconf-server:netconf-server.listen.endpoint", "index": "name"},
        {"key": "ucpe:config.interfaces:interface", "index": "name"},
        {"key": "ucpe:config.snmp-server:snmp-server.target-address", "index": "id"},
        {"key": "ucpe:config.snmp-server:snmp-server.users", "index": "id"},
        {"key": "ucpe:config.snmp-server:snmp-server.views", "index": "id"},
        {"key": "ucpe:config.syslog:syslog.remote-servers", "index": "id"}
    ]
    for item in index_list:
        if get_value(indexed, item['key']):
            indexed = set_value(indexed, item['key'], get_indexed_list(get_value(indexed, item['key']), item["index"]))
    for k, v in get_value(indexed, "ucpe:config.interfaces:interface").items():
        if not get_value(indexed, "ucpe:config.interfaces:interface.{}.tracehost.probes".format(k)):
            continue
        indexed = set_value(indexed, "ucpe:config.interfaces:interface.{}.tracehost.probes".format(k), get_indexed_list(get_value(indexed, "ucpe:config.interfaces:interface.{}.tracehost.probes".format(k)), "id"))
    return indexed


def config_value_set(config, values=dict):
    """
    Update values in string or dict using the values from another dict, similar to jinja2
    Example: config_value_set("Test {{ dev1.ip }}", {'dev1': {'ip': '10.3.72.11'}})
    Return: "Test 10.3.72.11"
    """
    for i in range(5):
        data = config
        if isinstance(data, dict):
            for key, value in data.items():
                data[key] = config_value_set(value, values=values)
        elif isinstance(data, list):
            items = list()
            for item in data:
                items.append(config_value_set(item, values=values))
            data = items
        elif isinstance(data, tuple):
            pass
        else:
            token_list = re.findall(r'{{(.*?)}}', str(config))
            for token in token_list:
                value = get_value(values, token.strip())
                if value is None:
                    raise Exception("Can't parse value {} for '{}'".format(token.strip(), config))
                if isinstance(value, dict) or isinstance(value, list):
                    data = value
                else:
                    vtype = type(value)
                    data = data.replace("{{" + token + "}}", str(value))
                    if data == str(value):
                        if vtype == bool:
                            data = str(value).lower() == 'true'
                        else:
                            data = vtype(data)
            if len(token_list) > 0:
                config = data
                continue
        return data
    raise Exception('Unresolved config values: {}'.format(config))


def merge_dict(src, dst, overwrite=False):
    """
    Merges two dictionaries
    :param src:
    :param dst:
    :param overwrite: If to overwrite the values in dst if exists
    :return: Merged dictionary
    """
    if dst is None or not isinstance(dst, dict):
        return src
    tmp = copy.deepcopy(dst)
    for key, value in dict(src).items():
        if isinstance(value, dict):
            if key not in tmp:
                tmp[key] = dict()
            tmp[key] = merge_dict(value, tmp[key], overwrite)
        elif isinstance(value, list):
            if key not in tmp:
                    tmp[key] = value
            elif isinstance(tmp[key], list):
                if len(tmp[key]):
                    # Merge lists by key index!
                    index = None
                    if isinstance(tmp[key][0], dict) and len(tmp[key][0]) == 1:
                        #take the key as index
                        index = list(tmp[key][0])[0]
                    elif 'id' in tmp[key][0]:
                        index = 'id'
                    elif 'name' in tmp[key][0]:
                        index = 'name'
                    elif 'type' in tmp[key][0]:
                        index = 'type'
                    if not index:
                        raise Exception("No index detected for key {}!".format(key))
                    indexed_src = get_indexed_list(value, index)
                    indexed_dst = get_indexed_list(tmp[key], index)
                    for i_k, i_v in indexed_src.items():
                        if get_value(indexed_dst, i_k):
                            indexed_dst[i_k] = merge_dict(i_v, indexed_dst[i_k], overwrite)
                        else:
                            indexed_dst[i_k] = i_v
                    tmp[key] = []
                    for i_k, i_v in indexed_dst.items():
                        tmp[key].append(i_v)
                else:
                    tmp[key] = value
            else:
                raise Exception("Can't merge {} with {}".format(tmp[key], value))
        elif isinstance(value, tuple):
            if overwrite:
                tmp[key] = value
            else:
                if key not in tmp:
                    tmp[key] = value
                elif isinstance(tmp[key], tuple):
                    tmp[key] = value
                else:
                    raise Exception("Can't merge {} with {}".format(tmp[key], value))
        else:
            if key not in tmp or overwrite:
                tmp[key] = value
    return tmp


def is_alive(host, port=22):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0


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


# Send message to the broker
def send_message(config, key, value, ex=None):
    redis_srv = redis.Redis(host=get_value(config, 'redis.host'),
                            password=get_value(config, 'redis.password'),
                            port=int(get_value(config, 'redis.port', 6378)),
                            socket_timeout=5,
                            socket_connect_timeout=60
                            )
    redis_srv.set("{}:{}:1".format(key, datetime.now(timezone.utc).timestamp()), value, ex=ex)
    redis_srv.close()


def update_message(config, key, value):
    redis_srv = redis.Redis(host=get_value(config, 'redis.host'),
                            password=get_value(config, 'redis.password'),
                            port=int(get_value(config, 'redis.port', 6378)),
                            socket_timeout=5,
                            socket_connect_timeout=60
                            )
    old_value = redis_srv.get(key)
    if old_value is None:
        redis_srv.close()
        return
    # old_value_str = old_value.decode('utf-8')
    redis_srv.set(key, value)
    redis_srv.close()


def delete_message(config, key):
    redis_srv = redis.Redis(host=get_value(config, 'redis.host'),
                            password=get_value(config, 'redis.password'),
                            port=int(get_value(config, 'redis.port', 6378)),
                            socket_timeout=5,
                            socket_connect_timeout=60
                            )
    value = redis_srv.get(key)
    if value is None:
        redis_srv.close()
        return
    redis_srv.delete(key)
    redis_srv.close()


def book_operation(config, key):
    global logger
    redis_srv = redis.Redis(host=get_value(config, 'redis.host'),
                            password=get_value(config, 'redis.password'),
                            port=int(get_value(config, 'redis.port', 6378)),
                            socket_timeout=5,
                            socket_connect_timeout=300
                            )
    sleep(uniform(0, 1))
    if redis_srv.get(key) is not None:
        redis_srv.close()
        logger.error('Booking {} failed'.format(key))
        return False
    redis_srv.set(key, 'booked', ex=60)     # Expire after 60 sec in case of raised exception during operation
    logger.debug('Booked {}'.format(key))
    redis_srv.close()
    return True


def send_notify(config, project_id, entry, message={}):
    global logger
    time.sleep(0.5)   # give time to db to update
    redis_srv = redis.Redis(host=get_value(config, 'redis.host'),
                            password=get_value(config, 'redis.password'),
                            port=int(get_value(config, 'redis.port', 6378)),
                            socket_timeout=5,
                            socket_connect_timeout=60
                            )
    message['project_id'] = project_id
    message[entry] = datetime.now(timezone.utc).isoformat()
    redis_srv.publish("{}.{}".format(entry, project_id), json.dumps(message))
    redis_srv.close()
    logger.debug("Notified: {}.{}".format(entry, project_id))


# GUI config functions
def validate_when_token(cfg, cfg_path, token):
    v = token.split(' ')
    if len(v) < 3:
        raise Exception("Error validating when token: {}".format(token))
    key = v[0]
    op = v[1]
    val = v[2].strip('"')
    if key.find('../') > -1:
        check_path = "{}.{}".format(cfg_path, key[key.rfind(':')+1:])
    else:
        raise Exception("Unhandled token: {}".format(token))
    if op == '=':
        return get_value(cfg, check_path) == val
    if op == '!=':
        return get_value(cfg, check_path) != val
    return True


def check_when(cfg, cfg_path, leaf):
    if 'when' not in leaf:
        return True
    # Parse OR
    if leaf['when'].find(' or ') > 0:
        for token in leaf['when'].split('or'):
            token = token.strip()
            if validate_when_token(cfg, cfg_path, token):
                return True
    # Parse AND
    elif leaf['when'].find(' and ') > 0:
        for token in leaf['when'].split('and'):
            token = token.strip()
            if not validate_when_token(cfg, cfg_path, token):
                return False
    else:
        return validate_when_token(cfg, cfg_path, leaf['when'])


def get_config_template(sch, cfg, interfaces, sch_path="ucpe:config", cfg_path="ucpe:config"):
    template = {}
    for name, val in get_value(sch, sch_path).items():
        if name == 'children':
            if get_value(sch, '{}.kind'.format(sch_path)) == 'list':
                key_name = get_value(sch, '{}.keys'.format(sch_path))[0]
                template[name] = []
                if cfg_path == 'ucpe:config.interfaces:interface':
                    for i in range(0, interfaces):
                        # Make ethernet interfaces data{i}
                        ifname = 'data{}'.format(i)
                        list_item = {}
                        for ch_name, ch_val in val.items():
                            kname = ch_name.replace(':', '_')
                            if ch_val == 'trace-host':  # Filter this as obsolete
                                continue
                            if not check_when(cfg, '{}[{}="{}"]'.format(cfg_path, key_name, ifname), ch_val):
                                continue
                            kind = get_value(ch_val, 'kind')
                            if kind == 'leaf':
                                list_item[kname] = copy.deepcopy(ch_val)
                                if ch_name == key_name:
                                    list_item[kname]['readonly'] = True
                                list_item[kname]['value'] = get_value(cfg, '{}[{}="{}"].{}'.format(cfg_path, key_name, ifname, ch_name))
                            else:
                                list_item[kname] = get_config_template(
                                    sch,
                                    cfg,
                                    interfaces,
                                    sch_path='{}.children.{}'.format(sch_path, ch_name),
                                    cfg_path='{}[{}="{}"]'.format(cfg_path, key_name, ifname)
                                )
                        template[name].append(list_item)
                    # Take the other interfaces from config
                    for interface in get_value(cfg, 'ucpe:config.interfaces:interface'):
                        if get_value(interface, 'type') == 'ethernet':
                            continue
                        ifname = get_value(interface, 'name')
                        list_item = {}
                        for ch_name, ch_val in val.items():
                            kname = ch_name.replace(':', '_')
                            kind = get_value(ch_val, 'kind')
                            if not check_when(cfg, '{}[{}="{}"]'.format(cfg_path, key_name, ifname), ch_val):
                                continue
                            if kind == 'leaf':
                                list_item[kname] = copy.deepcopy(ch_val)
                                list_item[kname]['value'] = get_value(cfg, '{}[{}="{}"].{}'.format(cfg_path, key_name, ifname, ch_name))
                            else:
                                list_item[kname] = get_config_template(
                                    sch,
                                    cfg,
                                    interfaces,
                                    sch_path='{}.children.{}'.format(sch_path, ch_name),
                                    cfg_path='{}[{}="{}"]'.format(cfg_path, key_name, ifname)
                                )
                        template[name].append(list_item)

                    # Add extendable interfaces
                    extendable_interfaces = {'vxlan': 99, 'loopback': 99, 'pppoe': interfaces}
                    for interface_type, max_count in extendable_interfaces.items():
                        list_item = {}
                        for ch_name, ch_val in val.items():
                            kname = ch_name.replace(':', '_')
                            kind = get_value(ch_val, 'kind')
                            if not check_when({"interfaces": {"type": interface_type}}, 'interfaces', ch_val):
                                continue
                            if kind == 'leaf':
                                list_item[kname] = copy.deepcopy(ch_val)
                                list_item[kname]['value'] = get_value(ch_val, 'default')
                            else:
                                list_item[kname] = get_config_template(
                                    sch,
                                    {},
                                    interfaces,
                                    sch_path='{}.children.{}'.format(sch_path, ch_name),
                                    cfg_path=''
                                )
                        template['_{}'.format(interface_type)] = copy.deepcopy(list_item)
                        template['_{}'.format(interface_type)]['_max'] = max_count

                    continue

                # Load the rest of the lists

                # Get the lists from config and check what should be extendable
                template['_{}'.format(key_name)] = get_config_template(sch, {}, 0, '{}.children'.format(sch_path))

                for item in get_value(cfg, cfg_path, []):
                    item_name = str(get_value(item, key_name))
                    list_item = {}
                    for ch_name, ch_val in val.items():
                        kname = ch_name.replace(':', '_')
                        kind = get_value(ch_val, 'kind')
                        if not check_when(cfg, '{}[{}="{}"]'.format(cfg_path, key_name, item_name), ch_val):
                            continue
                        if kind == 'leaf':
                            list_item[kname] = copy.deepcopy(ch_val)
                            list_item[kname]['value'] = get_value(cfg, '{}[{}="{}"].{}'.format(cfg_path, key_name, item_name, ch_name))
                        else:
                            list_item[kname] = get_config_template(
                                sch,
                                cfg,
                                interfaces,
                                sch_path='{}.children.{}'.format(sch_path, ch_name),
                                cfg_path='{}[{}="{}"]'.format(cfg_path, key_name, item_name)
                            )
                    template[name].append(list_item)
            else:
                template[name] = {}
                for ch_name, ch_val in val.items():
                    kname = ch_name.replace(':', '_')
                    kind = get_value(ch_val, 'kind')
                    if not check_when(cfg, cfg_path, ch_val):
                        continue
                    if kind == 'leaf':
                        template[name][kname] = copy.deepcopy(ch_val)
                        template[name][kname]['value'] = get_value(cfg, '{}.{}'.format(cfg_path, ch_name))
                    else:
                        template[name][kname] = get_config_template(
                            sch,
                            cfg,
                            interfaces,
                            sch_path='{}.children.{}'.format(sch_path, ch_name),
                            cfg_path='{}.{}'.format(cfg_path, ch_name)
                        )
        else:
            template[name] = copy.deepcopy(val)
    if cfg_path == "ucpe:config":
        template = {'ucpe_config': template}
    return template


def get_device_config_from_gui(gui_data):
    if isinstance(gui_data, dict):
        cfg = {}
        for k, v in gui_data.items():
            if 'children' in v:
                val = get_device_config_from_gui(v['children'])
                if isinstance(val, dict) and not val:
                    continue
                if isinstance(val, list) and len(val) == 0:
                    continue
                cfg[k] = val
            else:
                val = get_value(v, 'value')
                if val is not None:
                    cfg[k] = val
        return cfg
    if isinstance(gui_data, list):
        cfg = []
        for v in gui_data:
            cfg.append(get_device_config_from_gui(v))
        return cfg
    raise Exception("Unhandled gui data parsing case: {}".format(gui_data))


def execute_shell_command(cmd, shell=True, ignore_error=False):
    if cmd is str:
        cmd = str(cmd).split(' ')
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=shell
    )
    (stdout, stderr) = process.communicate()
    if len(stderr) > 0 and process.returncode > 0 and not ignore_error:
        raise Exception("Error executing command {}!\n{}".format(cmd, stderr))
    result = stdout.decode("utf-8")
    return result

