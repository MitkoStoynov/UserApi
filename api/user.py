from utils import *
from werkzeug.security import check_password_hash
import os
import sys
from connexion import request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from orm import *

config = json.loads(os.environ['monitor'])


def password_check(password):
    """
    Verify the strength of 'password'
    Returns a dict indicating the wrong criteria
    A password is considered strong if:
        8 characters length or more
        1 digit or more
        1 symbol or more
        1 uppercase letter or more
        1 lowercase letter or more
    """
    # calculating the length
    length_error = len(password) < 8
    # searching for digits
    digit_error = re.search(r"\d", password) is None
    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None
    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None
    # searching for symbols
    symbol_error = re.search(r"[ !@#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None
    # overall result
    password_ok = not (length_error or digit_error or uppercase_error or lowercase_error or symbol_error)
    return {
        'password_ok': password_ok,
        'length_error': length_error,
        'digit_error': digit_error,
        'uppercase_error': uppercase_error,
        'lowercase_error': lowercase_error,
        'symbol_error': symbol_error,
    }


def dump_full(p):
    return {
        "id": p[0].id,
        "username": p[0].username,
        "name": p[0].name,
        "description": p[0].description,
        "project_id": p[0].project_id,
        "project": p[2],
        "role_id": p[0].role_id,
        "role": p[4]
    }


def get_users(page=1, count=20, order='name', direction='asc'):
    try:
        cred = decode_manager_token("/home/mitko/PycharmProjects/monitoring/cert/jwtRSA256-public.pem", request.headers['X-Auth-Token'])
    except Exception as ex:
        return str(ex), 401
    db = Database()
    q = db.session.query(User, Project.id, Project.name, Role.id, Role.role).filter(User.project_id == Project.id)
    if not get_value(cred, 'is_super_user'):
        user = db.get_user(cred)
        q.filter(User.project_id == user.project_id)
    q = q.outerjoin(Role, User.role_id == Role.id)

    order_field = None
    if order == 'project':
        order_field = Project.name
    else:
        try:
            User.__getattribute__(User, order)
        except Exception as ex:
            return str(ex), 500
        order_field = User.__getattribute__(User, order)

    if direction == 'asc':
        q = q.order_by(asc(func.lower(order_field)))
    else:
        q = q.order_by(desc(func.lower(order_field)))

    q_cnt = q.count()
    q = q.limit(count).offset((page - 1) * count)
    return {'count': q_cnt, 'data': [dump_full(p) for p in q]}


def get_user(id):
    try:
        cred = decode_manager_token(get_value(config, 'token.public_file'), request.headers['X-Auth-Token'])
    except Exception as ex:
        return str(ex), 401
    db = Database()
    q = db.session.query(User, Project.id, Project.name, Role.id, Role.role).filter(User.project_id == Project.id)
    if not get_value(cred, 'is_super_user'):
        user = db.get_user(cred)
        q.filter(User.project_id == user.project_id)
    q = q.outerjoin(Role, User.role_id == Role.id)

    q = q.one_or_none()
    return dump_full(q) if q is not None else ("This user does not exists or no permission to see it!", 404)


def post_token(credentials):
    role = 0
    is_superuser = False
    if get_value(credentials, 'username', '1') == get_value(config, "admin.username",'2') and \
            check_password_hash(get_value(config, 'admin.password'), get_value(credentials, 'password')):
        is_superuser = True
    else:
        user = get_value(credentials, 'username', '')
        if user.find('@') < 0:
            return "Invalid Username format! It should contain the project, like 'admin@telco.com'!", 401
        db = Database()
        username = user[:user.rfind('@')]
        project_name = user[user.rfind('@') + 1:]
        project = db.session.query(Project).filter(Project.name == project_name).one_or_none()
        if project is None:
            return "Invalid credentials. Please try again.", 401
        res = db.session.query(User).filter(User.username == username, User.project_id == project.id).one_or_none()
        if res is None:
            return "Invalid credentials. Please try again.", 401
        if not check_password_hash(res.password, get_value(credentials, 'password')):
            return "Invalid credentials. Please try again.", 401
        role = res.group_id
    try:
        return get_manager_token(
            private_key_file=get_value(config, 'token.private_file'),
            user=get_value(credentials, 'username'),
            role=role,
            expire_hours=get_value(config, 'token.expire_hours', 24),
            is_superuser=is_superuser
        ), 200
    except Exception as ex:
        return ex, 401


# def token_info():
#     try:
#         cred = decode_manager_token(get_value(config, 'token.public_file'), request.headers['X-Auth-Token'])
#     except Exception as ex:
#         return str(ex), 401
#     cred['nbf'] = datetime.fromtimestamp(cred['nbf']).strftime("%d-%m-%Y %H:%M:%S")
#     cred['exp'] = datetime.fromtimestamp(cred['exp']).strftime("%d-%m-%Y %H:%M:%S")
#     db = Database()
#     cred['role_id'] = cred['role']
#     cred['role'] = user_group[cred['role']]
#     cred['is_readonly'] = False
#     if not cred['is_super_user']:
#         user = db.get_user(cred)
#         cred = merge_dict(get_user(user.id), cred, True)
#     else:
#         cred['project_id'] = 1
#         cred['project'] = get_value(config, 'default_project', 'telco.com')
#     return cred, 200
