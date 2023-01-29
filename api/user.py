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
    q = db.session.query(User, Project.id, Project.name, Role.id, Role.role).filter(User.project_id == Project.id, User.id == id, User.id > 0)
    if not get_value(cred, 'is_super_user'):
        user = db.get_user(cred)
        q.filter(User.project_id == user.project_id)
    q = q.outerjoin(Role, User.role_id == Role.id)

    q = q.one_or_none()
    return dump_full(q) if q is not None else ("This user does not exists or no permission to see it!", 404)


def put_user(user):
    try:
        cred = decode_manager_token(get_value(config, 'token.public_file'), request.headers['X-Auth-Token'])
    except Exception as ex:
        return str(ex), 401
    user['name'] = user['name'].strip()
    db = Database()
    current_user = None
    if not get_value(cred, 'is_super_user'):
        current_user = db.get_user(cred)
        print(current_user.role_id)
        if current_user.role_id > 2:
            return "Managing users is not allowed!", 403
        user['project_id'] = current_user.project_id

    p = db.session.query(User).filter(User.username == user['username'], User.project_id == user['project_id']).one_or_none()
    if p is not None:
        return "User with username '{}' already exists!".format(user['username']), 403
    if get_value(user, 'role_id', -1) not in range(1, 4):
        return "Wrong role_id! It must be in range [1-3]", 403
    if current_user and current_user.role_id > user['role_id']:
        return "Setting group with bigger rights than the current user is not allowed.", 403

    pass_result = password_check(user['password'])
    if not pass_result['password_ok']:
        return "Password must contain at least one uppercase letter, one lowercase letter, one digit, one special character and must have a minimum length of eight characters.", 406

    p = User()
    print(p.__tablename__)
    update_attributes(p, user)
    p.set_password(p.password)
    db.session.add(p)
    db.session.commit()
    db.session.flush()

    # send_action(config,
    #             cred,
    #             project_id=p.project_id,
    #             key="user:create",
    #             value=p.id,
    #             description="User {} was created".format(get_value(user, "username")))

    return p.id, 201


def post_user(id, user):
    try:
        cred = decode_manager_token(get_value(config, 'token.public_file'), request.headers['X-Auth-Token'])
    except Exception as ex:
        return str(ex), 401
    db = Database()
    current_user = None
    if not get_value(cred, 'is_super_user'):
        current_user = db.get_user(cred)
        if current_user.is_readonly:
            return "Current user is with read only permissions", 403
        if current_user.role_id > 1:
            return "Managing users is not allowed!", 403
        user['project_id'] = current_user.project_id
    p_ref = db.session.query(User).filter(User.username == user['username'], User.id != id, User.project_id == user['project_id']).one_or_none()
    if p_ref is not None:
        return "User with username '{}' already exists!".format(user['username']), 403
    p = db.session.query(User).filter(User.id == id).one_or_none()
    if p is None:
        return "This user does not exists!", 404
    if get_value(user, 'role_id', -1) not in range(1, 4):
        return "Wrong role_id! It must be in range [1-3]", 403
    if current_user and current_user.role_id > user['role_id']:
        return "Setting role with bigger rights than the current user is not allowed.", 403
    ##
    if 'password' in user and user['password']:
        pass_result = password_check(user['password'])
        if not pass_result['password_ok']:
            return "Password must contain at least one uppercase letter, one lowercase letter, one digit, one special character and must have a minimum length of eight characters.", 406

    if 'password' in user and user['password']:
        p.set_password(user['password'])
        del(user['password'])
    else:
        user['password'] = p.password
    update_attributes(p, user)
    db.session.commit()
    # send_action(config,
    #             cred,
    #             project_id=p.project_id,
    #             key="user:update",
    #             value=id,
    #             description="User {} was updated".format(get_value(user, "username")))
    return "User {} was updated".format(user['name']), 200


def delete_user(id):
    try:
        cred = decode_manager_token(get_value(config, 'token.public_file'), request.headers['X-Auth-Token'])
    except Exception as ex:
        return str(ex), 401
    db = Database()
    res = db.session.query(User).filter(User.id == id, User.id > 0)
    if not get_value(cred, 'is_super_user'):
        user = db.get_user(cred)
        if user.group_id > 2:
            return "Managing users is not allowed!", 403
        res = res.filter(User.project_id == user.project_id)
    res = res.one_or_none()
    if res is None:
        return "This user does not exists or no permissions for it!", 404
    # project_id = res.project_id
    # name = res.username
    db.delete_data_flow(User.__tablename__, id)

    # send_action(config=config,
    #             cred=cred,
    #             project_id=project_id,
    #             key="user:delete",
    #             value=id,
    #             description="User {} was deleted".format(name))
    return "User {} was deleted".format(id), 200


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
        role = res.role_id
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


def token_info():
    try:
        cred = decode_manager_token(get_value(config, 'token.public_file'), request.headers['X-Auth-Token'])
    except Exception as ex:
        return str(ex), 401
    print(cred)
    cred['nbf'] = datetime.fromtimestamp(cred['nbf']).strftime("%d-%m-%Y %H:%M:%S")
    cred['exp'] = datetime.fromtimestamp(cred['exp']).strftime("%d-%m-%Y %H:%M:%S")
    db = Database()
    cred['role_id'] = cred['role']
    cred['role'] = cred['role']
    if not cred['is_super_user']:
        user = db.get_user(cred)
        print(user)
        print(user.id)
        cred = merge_dict(get_user(user.id), cred, True)
    else:
        cred['project_id'] = 1
        cred['project'] = get_value(config, 'default_project', 'uktc.bg')
    return cred, 200
