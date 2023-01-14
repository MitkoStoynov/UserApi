import json
import os
import sys
from connexion import request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from orm import *
from utils import *

config = json.loads(os.environ['monitor'])


def dump_full(p):
    return {
        "id": p.id,
        "name": p.name,
        "description": p.description,
    }


def get_projects(page=1, count=20, order='name', direction='asc'):
    try:
        cred = decode_manager_token(get_value(config, 'token.public_file'), request.headers['X-Auth-Token'])
    except Exception as ex:
        return str(ex), 401
    db = Database()
    q = db.session.query(Project)
    if not get_value(cred, 'is_super_user'):
        q = q.filter(Project.name == get_value(cred, 'project'))
    try:
        Project.__getattribute__(Project, order)
    except Exception as ex:
        return str(ex), 500
    if direction == 'asc':
        q = q.order_by(Project.__getattribute__(Project, order).asc())
    else:
        q = q.order_by(Project.__getattribute__(Project, order).desc())
    q_cnt = q.count()
    q = q.limit(count).offset((page-1)*count)
    return {'count': q_cnt, 'data': [dump_full(p) for p in q]}


def get_project(id):
    try:
        cred = decode_manager_token(get_value(config, 'token.public_file'), request.headers['X-Auth-Token'])
    except Exception as ex:
        return str(ex), 401
    db = Database()
    if get_value(cred, 'is_super_user'):
        res = db.session.query(Project).filter(Project.id == id).one_or_none()
    else:
        res = db.session.query(Project).filter(Project.id == id, Project.name == get_value(cred, 'project')).one_or_none()
    return dump_full(res) if res is not None else ('Not found', 404)


def put_project(project):
    try:
        cred = decode_manager_token(get_value(config, 'token.public_file'), request.headers['X-Auth-Token'])
    except Exception as ex:
        return str(ex), 401
    if not get_value(cred, 'is_super_user'):
        return 'This operation is not allowed!', 403
    project['name'] = project['name'].strip()
    if project['name'].find(' ') > -1:
        return "Project name must be one word.", 403
    db = Database()
    p = db.session.query(Project).filter(Project.name == project['name']).one_or_none()
    if p is not None:
        return "Project with name '{}' already exists!".format(project['name']), 403
    n = Project()
    update_attributes(n, project)
    db.session.add(n)
    db.session.commit()
    db.session.flush()
    # Create default values in the database for this project
    return n.id, 201


def post_project(id, project):
    try:
        cred = decode_manager_token(get_value(config, 'token.public_file'), request.headers['X-Auth-Token'])
    except Exception as ex:
        return str(ex), 401
    if not get_value(cred, 'is_super_user'):
        return 'This operation is not allowed!', 403
    project['name'] = project['name'].strip()
    if project['name'].find(' ') > -1:
        return "Project name must be one word.", 403

    db = Database()
    p = db.session.query(Project).filter(Project.id == id).one_or_none()
    if p is None:
        return "This project does not exists!", 404
    p_ref = db.session.query(Project).filter(Project.name == project['name'], Project.id != id).one_or_none()
    if p_ref is not None:
        return "Project with name '{}' already exists!".format(project['name']), 403
    update_attributes(p, project)
    db.session.add(p)
    db.session.commit()
    return "Project {} was updated".format(project['name']), 200


# TODO: R&D delete_dataflow in orm
def delete_project(id):
    try:
        cred = decode_manager_token(get_value(config, 'token.public_file'), request.headers['X-Auth-Token'])
    except Exception as ex:
        return str(ex), 401
    if not get_value(cred, 'is_super_user'):
        return 'This operation is not allowed!', 403
    if id == 1:
        return 'This project is administratively protected from deletion!', 403
    db = Database()
    res = db.session.query(Project).filter(Project.id == id).one_or_none()
    if res is None:
        return "This project does not exists!", 404
    db.delete_data_flow(Project.__tablename__, id)
    return "Project was deleted", 200
