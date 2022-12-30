import os
import sys
from connexion import request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from orm import *

config = json.loads(os.environ['edge_config'])
logger.setLevel(get_value(config, 'log.level'))


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


def get_user_groups():
    try:
        cred = decode_manager_token(get_value(config, 'token.public_file'), request.headers['X-Auth-Token'])
    except Exception as ex:
        return str(ex), 401
    data = []
    for k,v in user_group.items():
        data.append({'id': k, 'name': v})
    return data


def token_info():
    try:
        cred = decode_manager_token(get_value(config, 'token.public_file'), request.headers['X-Auth-Token'])
    except Exception as ex:
        return str(ex), 401
    cred['nbf'] = datetime.fromtimestamp(cred['nbf']).strftime("%d-%m-%Y %H:%M:%S")
    cred['exp'] = datetime.fromtimestamp(cred['exp']).strftime("%d-%m-%Y %H:%M:%S")
    db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
    cred['role_id'] = cred['role']
    cred['role'] = user_group[cred['role']]
    cred['is_readonly'] = False
    if not cred['is_super_user']:
        user = db.get_user(cred)
        cred = merge_dict(get_user(user.id), cred, True)
    else:
        cred['project_id'] = 1
        cred['project'] = get_value(config, 'default_project', 'telco.com')
    return cred, 200


def dump_full(p):
    return {
        'id': p[0].id,
        'project_id': p[0].project_id,
        'operator_id': p[0].operator_id,
        'customer_id': p[0].customer_id,
        'project': p[2],
        'name': p[0].name,
        'contact': p[0].contact,
        'group_id': p[0].group_id,
        'group': user_group[p[0].group_id] if p[0].group_id in user_group else 'Unknown',
        'username': p[0].username,
        'operator_name': p[3] if p[3] else '',
        'customer_name': p[4] if p[4] else '',
        'is_readonly': p[0].is_readonly
    }


def get_users(page=1, count=20, order='name', direction='asc'):
    try:
        cred = decode_manager_token(get_value(config, 'token.public_file'), request.headers['X-Auth-Token'])
    except Exception as ex:
        return str(ex), 401
    db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
    q = db.session.query(User, Project.id, Project.name, Operator.name, Customer.name).filter(User.project_id == Project.id, User.id > 0)
    if not get_value(cred, 'is_super_user'):
        user = db.get_user(cred)
        q = q.filter(User.project_id == user.project_id)
        if user.operator_id:
            q = q.filter(Operator.id == user.operator_id)
        if user.customer_id:
            q = q.filter(Customer.id == user.customer_id)
    q = q.outerjoin(Operator, User.operator_id == Operator.id)
    q = q.outerjoin(Customer, User.customer_id == Customer.id)

    order_field = None

    if order == 'project':
        order_field = Project.name
    else:
        try:
            User.__getattribute__(User, order)
        except Exception as ex:
            logger.error(ex)
            return str(ex), 500
        order_field = User.__getattribute__(User, order)

    if direction == 'asc':
        q = q.order_by(asc(func.lower(order_field)))
    else:
        q = q.order_by(desc(func.lower(order_field)))

    q_cnt = q.count()
    q = q.limit(count).offset((page-1)*count)
    return {'count': q_cnt, 'data': [dump_full(p) for p in q]}


def get_user(id):
    try:
        cred = decode_manager_token(get_value(config, 'token.public_file'), request.headers['X-Auth-Token'])
    except Exception as ex:
        return str(ex), 401
    db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
    q = db.session.query(User, Project.id, Project.name, Operator.name, Customer.name).filter(User.project_id == Project.id, User.id == id, User.id > 0)
    if not get_value(cred, 'is_super_user'):
        user = db.get_user(cred)
        q = q.filter(User.project_id == user.project_id)
        if user.operator_id:
            q = q.filter(Operator.id == user.operator_id)
        if user.customer_id:
            q = q.filter(Customer.id == user.customer_id)
    q = q.outerjoin(Operator, User.operator_id == Operator.id)
    q = q.outerjoin(Customer, User.customer_id == Customer.id)
    q = q.one_or_none()
    return dump_full(q) if q is not None else ("This user does not exists or no permission to see it!", 404)


def put_user(user):
    try:
        cred = decode_manager_token(get_value(config, 'token.public_file'), request.headers['X-Auth-Token'])
    except Exception as ex:
        return str(ex), 401
    user['name'] = user['name'].strip()
    db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
    current_user = None
    if not get_value(cred, 'is_super_user'):
        current_user = db.get_user(cred)
        if current_user.is_readonly:
            return "Current user is with read only permissions", 403
        if current_user.group_id > 1:
            return "Managing users is not allowed!", 403
        user['project_id'] = current_user.project_id

    p = db.session.query(User).filter(User.username == user['username'], User.project_id == user['project_id']).one_or_none()
    if p is not None:
        return "User with username '{}' already exists!".format(user['username']), 403

    if get_value(user, 'group_id', -1) not in range(0, 3):
        return "Wrong group_id! It must be in range [0-2]", 403
    if current_user and current_user.group_id > user['group_id']:
        return "Setting group with bigger rights than the current user is not allowed.", 403
    if user['group_id'] >= 1:
        if not get_value(user, 'operator_id'):
            return "Please, specify operator for the user.", 403
        if current_user and current_user.group_id >= 1 and user['operator_id'] != current_user.operator_id:
            return "Setting another operator is not allowed.", 403
    if user['group_id'] >= 2:
        if not get_value(user, 'customer_id'):
            return "Please specify customer for the user.", 403
        if current_user and current_user.group_id >= 1:
            ref = db.session.query(Customer).filter(Customer.operator_id == current_user.operator_id, Customer.id == user['customer_id']).one_or_none()
            if not ref:
                return "Setting customer from different or missing operator is not allowed.", 403

    pass_result = password_check(user['password'])
    if not pass_result['password_ok']:
        return "Password must contain at least one uppercase letter, one lowercase letter, one digit, one special character and must have a minimum length of eight characters.", 406

    # Check operator_id and customer_id
    if user['group_id'] >= 1 and get_value(user, 'operator_id'):
        operator = db.session.query(Operator).filter(
            Operator.project_id == user['project_id'],
            Operator.id == get_value(user, 'operator_id')
        ).one_or_none()
        if not operator:
            return "Operator {} does not exists in database or is from different project.".format(get_value(user, 'operator_id')), 403
        if user['group_id'] >= 2 and get_value(user, 'customer_id'):
            customer = db.session.query(Customer).filter(
                Customer.project_id == user['project_id'],
                Customer.operator_id == get_value(user, 'operator_id'),
                Customer.id == get_value(user, 'customer_id')
            ).one_or_none()
            if not customer:
                return "Customer {} does not exists in database or is not in same operator.".format(get_value(user, 'customer_id')), 403

    logger.info('Create user: {}'.format(user['username']))
    p = User()
    update_attributes(p, user)
    p.set_password(p.password)
    db.session.add(p)
    db.session.commit()
    db.session.flush()
    send_notify(config, user['project_id'], 'user')
    return p.id, 201


def post_user(id, user):
    try:
        cred = decode_manager_token(get_value(config, 'token.public_file'), request.headers['X-Auth-Token'])
    except Exception as ex:
        return str(ex), 401
    db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
    current_user = None
    if not get_value(cred, 'is_super_user'):
        current_user = db.get_user(cred)
        if current_user.is_readonly:
            return "Current user is with read only permissions", 403
        if current_user.group_id > 1:
            return "Managing users is not allowed!", 403
        user['project_id'] = current_user.project_id
    p_ref = db.session.query(User).filter(User.username == user['username'], User.id != id, User.project_id == user['project_id']).one_or_none()
    if p_ref is not None:
        return "User with username '{}' already exists!".format(user['username']), 403
    p = db.session.query(User).filter(User.id == id).one_or_none()
    if p is None:
        return "This user does not exists!", 404
    if get_value(user, 'group_id', -1) not in range(0, 3):
        return "Wrong group_id! It must be in range [0-2]", 403
    if current_user and current_user.group_id > user['group_id']:
        return "Setting group with bigger rights than the current user is not allowed.", 403
    if user['group_id'] >= 1:
        if not get_value(user, 'operator_id'):
            return "Please, specify operator for the user.", 403
        if current_user and current_user.group_id >= 1 and user['operator_id'] != current_user.operator_id:
            return "Setting another operator is not allowed.", 403
    if user['group_id'] >= 2:
        if not get_value(user, 'customer_id'):
            return "Please specify customer for the user.", 403
        if current_user and current_user.group_id >= 1:
            ref = db.session.query(Customer).filter(Customer.operator_id == current_user.operator_id, Customer.id == user['customer_id']).one_or_none()
            if not ref:
                return "Setting customer from different or missing operator is not allowed.", 403

    if 'password' in user and user['password']:
        pass_result = password_check(user['password'])
        if not pass_result['password_ok']:
            return "Password must contain at least one uppercase letter, one lowercase letter, one digit, one special character and must have a minimum length of eight characters.", 406

    # Check operator_id and customer_id
    if user['group_id'] >= 1 and get_value(user, 'operator_id'):
        operator = db.session.query(Operator).filter(
            Operator.project_id == user['project_id'],
            Operator.id == get_value(user, 'operator_id')
        ).one_or_none()
        if not operator:
            return "Operator {} does not exists in database!".format(get_value(user, 'operator_id')), 403
        if user['group_id'] >= 2 and get_value(user, 'customer_id'):
            customer = db.session.query(Customer).filter(
                Customer.project_id == user['project_id'],
                Customer.operator_id == get_value(user, 'operator_id'),
                Customer.id == get_value(user, 'customer_id')
            ).one_or_none()
            if not customer:
                return "Customer {} does not exists in database or is not in same operator!".format(get_value(user, 'customer_id')), 403
        else:
            user['customer_id'] = 0
    else:
        user['operator_id'] = 0
    logger.info('Update user: {}'.format(user))
    if 'password' in user and user['password']:
        p.set_password(user['password'])
        del(user['password'])
    else:
        user['password'] = p.password
    update_attributes(p, user)
    db.session.commit()
    send_notify(config, user['project_id'], 'user')
    return "User {} was updated".format(user['name']), 200


def delete_user(id):
    try:
        cred = decode_manager_token(get_value(config, 'token.public_file'), request.headers['X-Auth-Token'])
    except Exception as ex:
        return str(ex), 401
    db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
    res = db.session.query(User).filter(User.id == id, User.id > 0)
    if not get_value(cred, 'is_super_user'):
        user = db.get_user(cred)
        if user.is_readonly:
            return "Current user is with read only permissions", 403
        if user.group_id > 1:
            return "Managing users is not allowed!", 403
        res = res.filter(User.project_id == user.project_id)
        if user.operator_id:
            res = res.filter(Operator.id == user.operator_id)
        if user.customer_id:
            res = res.filter(Customer.id == user.customer_id)
    res = res.one_or_none()
    if res is None:
        return "This user does not exists or no permissions for it!", 404
    logger.info('Delete user: {}'.format(res))
    project_id = res.project_id
    db.delete_data_flow(User.__tablename__, id)
    send_notify(config, project_id, 'user')
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
        db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
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

