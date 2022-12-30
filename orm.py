import copy
import os
import hashlib
from validators import ipv4_cidr, ipv6_cidr, ipv4, ipv6
from jsonschema import Draft4Validator
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, Boolean, create_engine, ForeignKey, func, and_, exists, or_, LargeBinary, UniqueConstraint, asc, desc
from sqlalchemy.orm import sessionmaker, relationship, backref, aliased
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import MetaData

from utils import *

STORAGE_CHUNK_SIZE = 50*1024*1024

Base = declarative_base()

severity_type = {
    0: 'Info',
    1: 'Warning',
    2: 'Normal',
    3: 'Critical'
}

operator_type = {
    0: 'Wholesaler',
    1: 'Main'
}

user_group = {
    0: 'Administrator',
    1: 'Operator',
    2: 'Customer'
}


class Project(Base):
    __tablename__ = "project"
    id = Column("id", Integer, primary_key=True,  autoincrement=True)
    name = Column("name", String(50), default='')
    description = Column("description", String(255), default='')
    __table_args__ = (UniqueConstraint('name', name='_project_uc'),)

    def dump(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description
        }


class User(Base):
    __tablename__ = "user"
    id = Column("id", Integer, primary_key=True,  autoincrement=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    name = Column("name", String(50), default='')
    contact = Column("contact", String(255), default='')
    group_id = Column("group_id", Integer, default=0)
    username = Column("username", String(50), default='')
    password = Column("password", String(128), default='')  # password hash, use set and check
    # https://dev.to/kaelscion/authentication-hashing-in-sqlalchemy-1bem
    operator_id = Column("operator_id", Integer, default=0)
    customer_id = Column("customer_id", Integer, default=0)
    is_readonly = Column("is_readonly", Boolean, default=0)
    __table_args__ = (UniqueConstraint('project_id', 'name', name='_user_uc'),)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def dump(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'name': self.name,
            'contact': self.contact,
            'group_id': self.group_id,
            'group': user_group[self.group_id] if self.group_id in user_group else 'Unknown',
            'username': self.username,
            'operator_id': self.operator_id,
            'customer_id': self.customer_id,
            'is_readonly': self.is_readonly
        }


class UserData(Base):
    __tablename__ = "user_data"
    id = Column("id", Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    user_id = Column(Integer, ForeignKey('user.id'))
    name = Column("name", String(100), default="")
    type = Column("type", String(255), default="")
    data = Column("file_name", Text, default="")
    __table_args__ = (UniqueConstraint('project_id', 'user_id', 'type', 'name', name='_user_data_uc'),)

    def dump(self):
        try:
            data = json.loads(self.data)
        except:
            data = self.data
        return {
            'id': self.id,
            'project_id': self.project_id,
            'user_id': self.user_id,
            'name': self.name,
            'type': self.type,
            'data': data
        }


class Operator(Base):
    __tablename__ = "operator"
    id = Column("id", Integer, primary_key=True,  autoincrement=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    name = Column("name", String(50), default='')
    type_id = Column("type_id", Integer, default=0)
    contact = Column("contact", String(255), default='')
    __table_args__ = (UniqueConstraint('project_id', 'name', name='_operator_uc'),)

    def dump(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'name': self.name,
            'type_id': self.type_id,
            'type': operator_type[self.type_id] if self.type_id in operator_type else 'Undefined',
            'contact': self.contact
        }


class Customer(Base):
    __tablename__ = "customer"
    id = Column("id", Integer, primary_key=True,  autoincrement=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    operator_id = Column(Integer, ForeignKey('operator.id'))
    name = Column("name", String(50), default='')
    market = Column("contact", String(255), default='')
    __table_args__ = (UniqueConstraint('project_id', 'operator_id', 'name', name='_customer_uc'),)

    def dump(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'operator_id': self.operator_id,
            'name': self.name,
            'market': self.market
        }


class Service(Base):
    __tablename__ = "service"
    id = Column("id", Integer, primary_key=True,  autoincrement=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    customer_id = Column(Integer, ForeignKey('customer.id'))
    name = Column("name", String(50), default='')
    service_type = Column("type", String(255), default='')
    topology = Column("topology", String(255), default='')
    __table_args__ = (UniqueConstraint('project_id', 'customer_id', 'name', name='_service_uc'),)

    def dump(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'customer_id': self.customer_id,
            'name': self.name,
            'service_type': self.service_type,
            'topology': self.topology
        }


class Site(Base):
    __tablename__ = "site"
    id = Column("id", Integer, primary_key=True,  autoincrement=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    service_id = Column(Integer, ForeignKey('service.id'))
    name = Column("name", String(50), default='')
    site_type = Column("type", String(255), default='')
    address = Column("address", String(255), default='')
    contact = Column("contact", String(255), default='')
    __table_args__ = (UniqueConstraint('project_id', 'service_id', 'name', name='_site_uc'),)

    def dump(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'service_id': self.service_id,
            'name': self.name,
            'site_type': self.site_type,
            'address': self.address,
            'contact': self.contact
        }


class HWType(Base):
    __tablename__ = "hwtype"
    id = Column("id", Integer, primary_key=True,  autoincrement=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    name = Column("name", String(50), default='')
    cpu_model = Column("cpu_model", String(100), default='')
    cpus = Column("cpus", Integer, default=1)
    interfaces = Column("interfaces", Integer, default=2)
    ram = Column("ram", Integer, default=1024)
    hdd = Column("hdd", Integer, default=20)
    __table_args__ = (UniqueConstraint('project_id', 'name', name='_hwtype_uc'),)

    def dump(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'name': self.name,
            'cpu_model': self.cpu_model,
            'cpus': self.cpus,
            'interfaces': self.interfaces,
            'ram': self.ram,
            'hdd': self.hdd
        }


class Status(Base):
    __tablename__ = "status"
    uid = Column("uid", String(50), primary_key=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    project = Column("project", String(100), default='')
    update_time = Column("update_time", TIMESTAMP)
    status = Column("status", String(50), default='unknown')
    hwtype = Column("hwtype", String(255), default='')
    version = Column("version", String(255), default='')
    management_ips = Column("management_ips", String(255), default='')
    operator = Column("operator", String(100), default='')
    customer = Column("customer", String(100), default='')
    service = Column("service", String(100), default='')
    site = Column("site", String(100), default='')
    is_ignored = Column("is_ignored", Boolean, default=0)
    is_app_support = Column("is_app_support", Boolean, default=0)
    app_list = Column("app_list", Text, default='')
    data = Column("data", Text, default='')
    __table_args__ = (UniqueConstraint('project_id', 'uid', name='_status_uc'),)

    def dump(self):
        return {
            'project_id': self.project_id,
            'project': self.project,
            'operator': self.operator,
            'customer': self.customer,
            'service': self.service,
            'site': self.site,
            'uid': self.uid,
            'update_time': self.update_time,
            'status': self.status,
            'hwtype': self.hwtype,
            'version': self.version,
            'management_ips': self.management_ips,
            'is_ignored': self.is_ignored,
            'is_app_support': self.is_app_support,
            'app_list': self.app_list,
            'data': self.data
        }


class ControllerStatus(Base):
    __tablename__ = "controller_status"
    hostname = Column("hostname", String(100), primary_key=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    project = Column("project", String(100), default='')
    status = Column("status", String(50), default='unknown')
    version = Column("version", String(255), default='')
    management_ips = Column("management_ips", String(255), default='')
    operator = Column("operator", String(100), default='')
    customer = Column("customer", String(100), default='')
    data = Column("data", Text, default='')
    update_time = Column("update_time", TIMESTAMP)
    is_ignored = Column("is_ignored", Boolean, default=0)
    __table_args__ = (UniqueConstraint('project_id', 'hostname', name='_controller_status_uc'),)

    def dump(self):
        return {
            'hostname': self.hostname,
            'project_id': self.project_id,
            'project': self.project,
            'operator': self.operator,
            'customer': self.customer,
            'update_time': self.update_time,
            'status': self.status,
            'version': self.version,
            'management_ips': self.management_ips,
            'is_ignored': self.is_ignored,
            'data': self.data
        }


class Controller(Base):
    __tablename__ = "controller"
    id = Column("id", Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    customer_id = Column(Integer, ForeignKey('customer.id'))
    hostname = Column("hostname", String(100), default="")
    admin_status = Column("admin_status", String(50), default="unknown")
    username = Column("username", String(100), default="")
    password = Column("password", String(100), default="")
    description = Column("description", String(255), default="")
    kub_config = Column("kub_config", Text, default="")
    is_local = Column("is_local", Boolean, default=0)
    __table_args__ = (UniqueConstraint('project_id', 'hostname', name='_controller_uc'),)

    def dump(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'customer_id': self.customer_id,
            'admin_status': self.admin_status,
            'hostname': self.hostname,
            'username': self.username,
            'password': self.password,
            'description': self.description,
            'is_local': self.is_local
        }


class Node(Base):
    __tablename__ = "node"
    id = Column("id", Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    site_id = Column(Integer, ForeignKey('site.id'))
    hwtype_id = Column(Integer, ForeignKey('hwtype.id'))
    uid = Column("uid", String(50), default="")
    controller_id = Column("controller_id", Integer, default=0)
    admin_status = Column("admin_status", String(50), default="unknown")
    username = Column("username", String(100), default="")
    password = Column("password", String(100), default="")
    hostname = Column("hostname", String(100), default="")
    description = Column("description", String(255), default="")
    auth2factor = Column("auth2factor", Boolean, default=0)
    is_kubernetes = Column("is_kubernetes", Boolean, default=1)
    is_application = Column("is_application", Boolean, default=0)
    is_cbox = Column("is_cbox", Boolean, default=0)
    __table_args__ = (UniqueConstraint('project_id', 'site_id', 'uid', name='_node_uc'),)

    def dump(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'site_id': self.site_id,
            'hwtype_id': self.hwtype_id,
            'uid': self.uid,
            'controller_id': self.controller_id,
            'admin_status': self.admin_status,
            'username': self.username,
            'password': self.password,
            'hostname': self.hostname,
            'description': self.description,
            'auth2factor': self.auth2factor,
            'is_kubernetes': self.is_kubernetes,
            'is_application': self.is_application,
            'is_cbox': self.is_cbox
        }


class Config(Base):
    __tablename__ = "config"
    id = Column("id", Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    node_id = Column(Integer, ForeignKey('node.id'))
    uid = Column("uid", String(50))
    update_time = Column("update_time", TIMESTAMP)
    device_config = Column("device_config", Text)
    schema_version = Column(Integer, default=0)
    device_schema = Column("device_schema", Text)
    manager_config = Column("manager_config", Text)
    device_get_time = Column("device_get_time", TIMESTAMP)
    __table_args__ = (UniqueConstraint('project_id', 'node_id', 'uid', name='_config_uc'),)

    def dump(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'node_id': self.node_id,
            'uid': self.uid,
            'update_time': self.update_time if self.update_time else '',
            'device_get_time': self.device_get_time if self.device_get_time else '',
            'device_config': json.loads(self.device_config) if self.device_config else {},
            'device_schema': json.loads(self.device_schema) if self.device_schema else {},
            'manager_config': json.loads(self.manager_config) if self.manager_config else {}
        }


class NodeTemplate(Base):
    __tablename__ = "node_template"
    id = Column("id", Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    operator_id = Column("operator_id", Integer, default=0)
    customer_id = Column("customer_id", Integer, default=0)
    name = Column("name", String(255))
    schema_version = Column(Integer, default=0)
    template = Column("template", Text)

    def dump(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'operator_id': self.operator_id,
            'customer_id': self.customer_id,
            'schema_version': self.schema_version,
            'template': json.loads(self.template) if self.template else {}
        }


class Event(Base):
    __tablename__ = "event"
    id = Column("id", Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    name = Column("name", String(50))
    type = Column("type", String(20))
    type_id = Column("type_id", Integer, default=0)
    severity_id = Column("severity_id", Integer, default=0)
    is_alarm = Column("is_alarm", Boolean, default=0)
    is_active = Column("is_active", Boolean, default=0)
    is_ack = Column("is_ack", Boolean, default=0)
    ack_reason = Column("ack_reason", String(255), default='')
    update_time = Column("update_time", TIMESTAMP)
    key = Column("key", String(50))
    value = Column("value", String(50))
    description = Column("description", Text)
    corrective_action = Column("corrective_action", String(255))
    __table_args__ = (UniqueConstraint('project_id', 'update_time', 'key', 'value', 'type', 'type_id', name='_event_uc'),)

    def dump(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'name': self.name,
            'type': self.type,
            'type_id': self.type_id,
            'severity_id': self.severity_id,
            'severity': severity_type[self.severity_id] if self.severity_id in severity_type else 'Undefined',
            'is_alarm': self.is_alarm,
            'is_active': self.is_active,
            'is_ack': self.is_ack,
            'ack_reason': self.ack_reason,
            'update_time': self.update_time,
            'key': self.key,
            'value': self.value,
            'description': self.description,
            'corrective_action': self.corrective_action
        }


class AppCatalog(Base):
    __tablename__ = "app_catalog"
    id = Column("id", Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    name = Column("name", String(100))
    version = Column("version", String(50))
    description = Column("description", String(255))
    config = Column("config", Text)
    app_template = Column("app_template", Text)
    user_data = Column("user_data", Text)
    is_reboot = Column("is_reboot", Boolean, default=0)
    __table_args__ = (UniqueConstraint('project_id', 'name', 'version', name='_appcatalog_uc'),)

    def dump(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'config': json.loads(self.config) if self.config else {},
            'app_template': json.loads(self.app_template) if self.app_template else {},
            'user_data': json.loads(self.user_data) if self.user_data else {},
            'is_reboot': self.is_reboot
        }


class AppNode(Base):
    __tablename__ = "app_node"
    id = Column("id", Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    node_id = Column(Integer, ForeignKey('node.id'))
    app_id = Column(Integer, ForeignKey('app_catalog.id'))
    is_active = Column("is_active", Boolean, default=0)
    admin_status = Column("admin_status", String(50), default="")
    app_template = Column("app_template", Text)
    user_data = Column("user_data", Text)
    __table_args__ = (UniqueConstraint('project_id', 'node_id', 'app_id', name='_appnode_uc'),)

    def dump(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'node_id': self.node_id,
            'app_id': self.app_id,
            'is_active': self.is_active,
            'app_template': json.loads(self.app_template) if self.app_template else {},
            'user_data': json.loads(self.user_data) if self.user_data else {}
        }


class ImageCatalog(Base):
    __tablename__ = "image_catalog"
    id = Column("id", Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    customer_id = Column(Integer, ForeignKey('customer.id'))
    name = Column("name", String(100))
    tag = Column("tag", String(50), default='')
    type = Column("type", String(50), default='')
    is_remote = Column("is_remote", Boolean, default=0)
    description = Column("description", String(255), default='')
    file_name = Column("file_name", String(100), default='')
    __table_args__ = (UniqueConstraint('project_id', 'customer_id', 'name', 'tag', name='_imagecatalog_uc'),)

    def dump(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'customer_id': self.customer_id,
            'name': self.name,
            'tag': self.tag,
            'type': self.type,
            'is_remote': self.is_remote,
            'description': self.description,
            'file_name': self.file_name
        }


class ImageController(Base):
    __tablename__ = "image_controller"
    id = Column("id", Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey('project.id'), primary_key=True)
    image_id = Column(Integer, ForeignKey('image_catalog.id'), primary_key=True)
    controller_id = Column(Integer, ForeignKey('controller.id'), primary_key=True)
    __table_args__ = (UniqueConstraint('project_id', 'image_id', 'controller_id', name='_imagecontroller_uc'),)

    def dump(self):
        return {
            'project_id': self.project_id,
            'image_id': self.image_id,
            'controller_id': self.controller_id
        }


class KubServiceTemplate(Base):
    __tablename__ = "kub_template"
    id = Column("id", Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    customer_id = Column(Integer, ForeignKey('customer.id'))
    hwtype_id = Column("hwtype_id", Integer, default=0)
    resources = Column("resources", Text, default='{}')
    name = Column("name", String(100))
    description = Column("description", String(255), default='')
    template = Column("template", Text, default='')
    design = Column("design", Text, default='')
    params = Column("params", Text, default='{}')
    __table_args__ = (UniqueConstraint('project_id', 'customer_id', 'name', name='_kubservicetemplate_uc'),)

    def dump(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'customer_id': self.customer_id,
            'hwtype_id': self.hwtype_id,
            'name': self.name,
            'description': self.description,
            'template': self.template,
            'design': self.design,
            'params': json.loads(self.params),
            'resources': json.loads(self.resources)
        }


class KubService(Base):
    __tablename__ = "kub_service"
    id = Column("id", Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    node_id = Column(Integer, ForeignKey('node.id'))
    template_id = Column("template_id", ForeignKey('kub_template.id'))
    name = Column("name", String(100))
    description = Column("description", String(255), default='')
    params = Column("params", Text, default='{}')
    admin_status = Column("admin_status", String(50), default="")
    oper_status = Column("oper_status", String(50), default="")
    __table_args__ = (UniqueConstraint('project_id', 'node_id', 'template_id', 'name', name='_kubservice_uc'),)

    def dump(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'node_id': self.node_id,
            'template_id': self.template_id,
            'name': self.name,
            'description': self.description,
            'params': json.loads(self.params),
            'admin_status': self.admin_status,
            'oper_status': self.oper_status
        }


class Storage(Base):
    __tablename__ = "storage"
    id = Column("id", Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    file_index = Column("file_index", String(255), default="")
    file_name = Column("file_name", String(255), default="")
    chunk_num = Column("chunk_num", Integer, default=1)
    chunk_total = Column("chunk_total", Integer, default=1)
    data = Column("data", LargeBinary)
    __table_args__ = (UniqueConstraint('project_id', 'file_index', 'chunk_num', name='_storage_uc'),)

    def dump(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'file_name': self.file_name,
            'file_index': self.file_index,
            'chunk_num': self.chunk_num,
            'chunk_total': self.chunk_total

        }


def update_attributes(obj, data):
    for column in obj.__table__.columns:
        if column.key == 'id':
            continue
        if column.key not in data:
            continue
        if column.type.python_type is str:
            val = get_value(data, column.key, '')
            if column.type.length and len(val) > column.type.length:
                raise Exception('Field "{}" has maximum length of {} symbols. Now it is {} symbols.'.format(column.key, column.type.length, len(val)))
        if column.type.python_type is int:
            val = get_value(data, column.key, '')
            if not isinstance(val ,int):
                raise Exception('Field "{}" is not integer. Now it is "{}".'.format(column.key, val))
    for key, val in data.items():
        if key == 'id':
            continue
        if hasattr(obj, key):
            v = get_value(data, key, getattr(obj, key))
            if isinstance(v, dict):
                v = json.dumps(v)
            setattr(obj, key, v)


class ManagerDB:
    engine = None
    session = None
    database_engine = "sqlite:///:memory:"
    debug = False

    def initialize_database(self, config={}):
        m = MetaData()
        m.reflect(self.engine)
        tables = m.tables.keys()
        Base.metadata.create_all(bind=self.engine)
        if 'project' not in tables:
            data_list = [
                [get_value(config, 'default_project', 'uktc.com'), 'Default system project']
            ]
            projects = []
            for v in data_list:
                projects.append(Project(name=v[0], description=v[1]))
            self.session.bulk_save_objects(projects)
            self.session.commit()
            self.initialize_project(project_id=1, config=config)
        if 'user' not in tables:
            super_user = User()
            super_user.id = 0
            super_user.project_id = 1
            super_user.name = 'Super User'
            super_user.contact = 'System administrator administrative account'
            self.session.add(super_user)
            self.session.commit()

    def __init__(self, database_engine="sqlite:///:memory:", debug=False):
        self.database_engine = database_engine
        self.debug = debug
        self.engine = create_engine(database_engine, echo=debug, isolation_level="READ UNCOMMITTED", pool_pre_ping=True)
        session = sessionmaker(bind=self.engine)
        self.session = session()

    def get_session(self):
        return self.session

    def get_indexed_list(self, obj, key='id'):
        res = self.session.query(obj).all()
        data = {}
        for v in res:
            v = v.dump()
            data[v[key]] = v
        return data

    def full_dump(self, obj, q):
        keys = {}
        for v in obj.__dict__:
            if not v.startswith("_") and not callable(getattr(obj, v, None)) and v.find('_') > 0:
                parts = v.split('_')
                if len(parts) > 2:
                    continue
                if parts[0].capitalize() in globals():
                    keys[v] = self.get_indexed_list(globals()[parts[0].capitalize()])
        res = []
        for p in q:
            data = p.dump()
            data_keys = list(data.keys())[:]
            for v in data_keys:
                parts = v.split('_')
                if len(parts) != 2:
                    continue
                if parts[0].capitalize() in globals():
                    data[parts[0]] = keys[v][data[v]]
            res.append(data)
        return res

    def __del__(self):
        try:
            self.session.close()
            self.engine.dispose()
        except Exception as ex:
            logger.error(ex)

    def get_dependencies_list(self, table_name, id, exclude_list=[]):
        use_list = []
        if self.session.bind.dialect.name == 'postgresql':
            query = "select foo.table_name, foo.column_name " + \
                    "from ( " + \
                    "    select " + \
                    "        pgc.contype as constraint_type, " + \
                    "        ccu.table_schema as table_schema, " + \
                    "        kcu.table_name as table_name, " + \
                    "        case when (pgc.contype = 'f') then kcu.column_name else ccu.column_name end as column_name, " + \
                    "        case when (pgc.contype = 'f') then ccu.table_name else (null) end as reference_table, " + \
                    "        case when (pgc.contype = 'f') then ccu.column_name else (null) end as reference_col, " + \
                    "        case when (pgc.contype = 'p') then 'yes' else 'no' end as auto_inc, " + \
                    "        case when (pgc.contype = 'p') then 'no' else 'yes' end as is_nullable, " + \
                    "        'integer' as data_type, " + \
                    "        '0' as numeric_scale, " + \
                    "        '32' as numeric_precision " + \
                    "    from " + \
                    "        pg_constraint as pgc " + \
                    "        join pg_namespace nsp on nsp.oid = pgc.connamespace " + \
                    "        join pg_class cls on pgc.conrelid = cls.oid " + \
                    "        join information_schema.key_column_usage kcu on kcu.constraint_name = pgc.conname " + \
                    "        left join information_schema.constraint_column_usage ccu on pgc.conname = ccu.constraint_name " + \
                    "        and nsp.nspname = ccu.constraint_schema " + \
                    "     union " + \
                    "        select " + \
                    "            null as constraint_type , " + \
                    "            table_schema, " + \
                    "            table_name, " + \
                    "            column_name, " + \
                    "            null as refrence_table, " + \
                    "            null as refrence_col, " + \
                    "            'no' as auto_inc, " + \
                    "            is_nullable, " + \
                    "            data_type, " + \
                    "            numeric_scale, " + \
                    "            numeric_precision " + \
                    "        from information_schema.columns cols " + \
                    "        where " + \
                    "           table_schema = 'public' " + \
                    "            and concat(table_name, column_name) not in( " + \
                    "                select concat(kcu.table_name, kcu.column_name) " + \
                    "                from " + \
                    "                pg_constraint as pgc " + \
                    "                join pg_namespace nsp on nsp.oid = pgc.connamespace " + \
                    "                join pg_class cls on pgc.conrelid = cls.oid " + \
                    "                join information_schema.key_column_usage kcu on kcu.constraint_name = pgc.conname " + \
                    "                left join information_schema.constraint_column_usage ccu on pgc.conname = ccu.constraint_name " + \
                    "                and nsp.nspname = ccu.constraint_schema " + \
                    "            ) " + \
                    "    ) as foo " + \
                    "where foo.reference_table is not Null and foo.reference_table = '{}'".format(table_name)
            table_list = self.session.execute(query)
            # for table in table_list:
            #     for row in self.session.execute('SELECT COUNT(*) FROM public.{} WHERE {}={}'.format(table[0], table[1], id)):
            #         if row[0] > 0 and table[0] not in exclude_list:
            #             use_list.append("{}({})".format(table[0], row[0]))
            for table in table_list:
                val = {'table': table[0], 'field': table[1]}
                for row in self.session.execute('SELECT COUNT(*) FROM public.{} WHERE {}={}'.format(table[0], table[1], id)):
                    if row[0] > 0 and table[0] not in exclude_list:
                        val['count'] = row[0]
                        use_list.append(val)
            return use_list
        else:
            db_name = None
            for row in self.session.execute('SELECT DATABASE()'):
                db_name = row[0]
                break
            if not db_name:
                return use_list
            table_list = self.session.execute(
                'SELECT ' +
                'TABLE_NAME,COLUMN_NAME,CONSTRAINT_NAME, REFERENCED_TABLE_NAME,' +
                'REFERENCED_COLUMN_NAME ' +
                'FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE ' +
                'WHERE REFERENCED_TABLE_SCHEMA = "{}" AND '.format(db_name) +
                'REFERENCED_TABLE_NAME = "{}"'.format(table_name)
            )
            for table in table_list:
                val = {'table': table[0], 'field': table[1]}
                for row in self.session.execute('SELECT COUNT(*) FROM {} WHERE {}={}'.format(table[0], table[1], id)):
                    if row[0] > 0 and table[0] not in exclude_list:
                        val['count'] = row[0]
                        use_list.append(val)
            return use_list

    def get_dependencies(self, table_name, id, exclude_list=[]):
        use_list = []
        for val in self.get_dependencies_list(table_name, id, exclude_list):
            use_list.append("{}({})".format(val['table'], val['count']))
        return use_list

    def delete_data_flow(self, table_name, id, exclude_list=[]):
        for val in self.get_dependencies_list(table_name, id, exclude_list):
            if self.session.bind.dialect.name == 'postgresql':
                data = self.session.execute("SELECT ID FROM public.{} WHERE {}={}".format(val['table'], val['field'], id))
            else:
                data = self.session.execute("SELECT ID FROM {} WHERE {}={}".format(val['table'], val['field'], id))
            for row in data:
                self.delete_data_flow(val['table'], row[0], exclude_list=exclude_list)
        if self.session.bind.dialect.name == 'postgresql':
            self.session.execute("DELETE FROM public.{} WHERE ID={}".format(table_name, id))
        else:
            self.session.execute("DELETE FROM {} WHERE ID={}".format(table_name, id))
        self.session.commit()

    def set_node_status(self, id, status):
        self.session.execute("UPDATE node SET admin_status='{}' WHERE id={}".format(status, id))
        self.session.commit()

    def get_user(self, cred):
        project = self.session.query(Project).filter(Project.name == cred['project']).one_or_none()
        if not project:
            raise Exception("Project '{}' not found in database.".format(cred['project']))
        user = self.session.query(User).filter(User.username == cred['username'], User.project_id == project.id).one_or_none()
        if not user:
            raise Exception("User '{}' not found in database.".format(cred['username']))
        return user

    def is_node_allowed(self, user, node_id):
        node = self.session.query(Node, Operator.id, Customer.id, Service.id, Site.id).filter(
            Node.id == node_id,
            Node.project_id == user.project_id,
            Node.site_id == Site.id,
            Site.service_id == Service.id,
            Service.customer_id == Customer.id,
            Customer.operator_id == Operator.id,
            Operator.project_id == Node.project_id
        )
        if user.group_id >= 1 and user.operator_id:
            node = node.filter(Operator.id == user.operator_id)
        if user.group_id >= 2 and user.customer_id:
            node = node.filter(Customer.id == user.customer_id)
        node = node.one_or_none()
        return node is not None

    def is_controller_allowed(self, user, controller_id):
        controller = self.session.query(Controller, Operator.id, Customer.id).filter(
            Controller.id == controller_id,
            Controller.project_id == user.project_id,
            Controller.customer_id == Customer.id,
            Customer.operator_id == Operator.id,
            Operator.project_id == Controller.project_id
        )
        if user.group_id >= 1 and user.operator_id:
            controller = controller.filter(Operator.id == user.operator_id)
        if user.group_id >= 2 and user.customer_id:
            controller = controller.filter(Customer.id == user.customer_id)
        controller = controller.one_or_none()
        return controller is not None

    def get_allowed_node_ids(self, user):
        nodes = self.session.query(Node.id, Operator.id, Customer.id, Service.id, Site.id).filter(
            Node.project_id == user.project_id,
            Node.site_id == Site.id,
            Site.service_id == Service.id,
            Service.customer_id == Customer.id,
            Customer.operator_id == Operator.id,
            Operator.project_id == Node.project_id
        )
        if user.group_id >= 1 and user.operator_id:
            nodes = nodes.filter(Operator.id == user.operator_id)
        if user.group_id >= 2 and user.customer_id:
            nodes = nodes.filter(Customer.id == user.customer_id)
        nodes = nodes.all()
        node_ids = []
        for node in nodes:
            if node[0] not in node_ids:
                node_ids.append(node[0])
        return node_ids

    def get_allowed_controller_ids(self, user):
        controllers = self.session.query(Controller.id, Operator.id, Customer.id).filter(
            Controller.project_id == user.project_id,
            Controller.customer_id == Customer.id,
            Customer.operator_id == Operator.id,
            Operator.project_id == Controller.project_id

        )
        if user.group_id >= 1 and user.operator_id:
            controllers = controllers.filter(Operator.id == user.operator_id)
        if user.group_id >= 2 and user.customer_id:
            controllers = controllers.filter(Customer.id == user.customer_id)
        controllers = controllers.all()
        controller_ids = []
        for controller in controllers:
            if controller[0] not in controller_ids:
                controller_ids.append(controller[0])
        return controller_ids


def sync_node_config(config, data, manager_config):
    db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
    project_name = get_value(manager_config, 'ucpe:config.system:system.project')
    project_id = 1
    if project_name:
        q = db.session.query(Project).filter(Project.name == project_name).one_or_none()
        if q:
            project_id = q.id
            if isinstance(data, Node):
                data.project_id = q.id
            else:
                data['project_id'] = q.id
    hostname = get_value(manager_config, 'ucpe:config.system:system.hostname')
    if hostname:
        if isinstance(data, Node):
            data.hostname = hostname
        else:
            data['hostname'] = hostname
    site_name = get_value(manager_config, 'ucpe:config.system:system.site')
    site_id = None
    service_id = None
    if site_name:
        q = db.session.query(Site).filter(Site.name == site_name, Site.project_id == project_id).one_or_none()
        if not q:
            raise Exception("Missing site '{}' in the database for the node".format(site_name))
        site_id = q.id
        service_id = q.service_id
    if isinstance(data, Node):
        data.site_id = site_id
    else:
        data['site_id'] = site_id

    hwtype = get_value(manager_config, 'ucpe:status.system:system.hwtype')
    if hwtype:
        q = db.session.query(HWType).filter(HWType.name == hwtype, HWType.project_id == project_id).one_or_none()
        if q:
            if isinstance(data, Node):
                data.hwtype_id = q.id
            else:
                data['hwtype_id'] = q.id

    controller_id = 0
    is_cbox = get_value(manager_config, 'ucpe:config.kubernetes:kubernetes.cbox.enabled', False)
    if isinstance(data, Node):
        data.is_cbox = is_cbox
    else:
        data['is_cbox'] = is_cbox
    if is_cbox:
        # Create local controller if not exits
        controller = db.session.query(Controller).filter(Controller.project_id == project_id, Controller.hostname == hostname, Controller.is_local == True).one_or_none()
        if controller:
            controller_id = controller.id
        else:
            controller = Controller()
            controller.hostname = hostname
            controller.project_id = project_id
            if isinstance(data, Node):
                controller.description = data.description
            else:
                controller.description = get_value(data, 'description', '')
            controller.is_local = True
            service = db.session.query(Service).filter(Service.project_id == project_id, Service.id == service_id).one_or_none()
            if not service:
                raise Exception("Missing service '{}' in the database for the node".format(service_id))
            controller.customer_id = service.customer_id
            controller_status = 'unknown'
            if isinstance(data, Node):
                uid = data.uid
            else:
                uid = data['uid']
            status = db.session.query(Status).filter(Status.project_id == project_id, Status.uid == uid).one_or_none()
            if status:
                controller_status = status.status
            controller.admin_status = controller_status
            if isinstance(data, Node):
                controller.username = data.username
                controller.password = data.password
            else:
                controller.username = get_value(data, 'username', 'admin')
                controller.password = get_value(data, 'password', 'Nfv@admin21')
            db.session.add(controller)
            db.session.commit()
            db.session.flush()
            controller_id = controller.id
    else:
        # Delete local controller if not exits
        controller = db.session.query(Controller).filter(Controller.project_id == project_id, Controller.hostname == hostname, Controller.is_local == True).one_or_none()
        if controller:
            db.delete_data_flow(Controller.__tablename__, controller.id)

        controller_name = get_value(manager_config, 'ucpe:config.kubernetes:kubernetes.controller')
        if controller_name:
            controller = db.session.query(Controller).filter(Controller.project_id == project_id, Controller.hostname == controller_name).one_or_none()
            if controller:
                controller_id = controller.id
    if isinstance(data, Node) and controller_id > 0:
        data.controller_id = controller_id
    else:
        data['controller_id'] = controller_id

    if isinstance(data, Node):
        data.is_kubernetes = get_value(manager_config, 'ucpe:config.system:system.capabilities.worker-kubernetes', 'disabled') == 'enabled'
        data.is_application = get_value(manager_config, 'ucpe:config.system:system.capabilities.native-applications', 'disabled') == 'enabled'
    else:
        data['is_kubernetes'] = get_value(manager_config, 'ucpe:config.system:system.capabilities.worker-kubernetes', 'disabled') == 'enabled'
        data['is_application'] = get_value(manager_config, 'ucpe:config.system:system.capabilities.native-applications', 'disabled') == 'enabled'
    return data


def apply_node_config(config, node, manager_config):
    if not isinstance(node, Node):
        my_node = Node()
        update_attributes(my_node, node)
        node = my_node
    new_config = copy.deepcopy(manager_config)
    db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
    if not node.hostname:
        raise Exception("Missing node hostname.")
    new_config = set_value(new_config, 'ucpe:config.system:system.hostname', node.hostname)
    project = db.session.query(Project).filter(Project.id == node.project_id).one_or_none()
    if not project:
        raise Exception("Missing project with id {}.".format(node.project_id))
    new_config = set_value(new_config, 'ucpe:config.system:system.project', project.name)
    site = db.session.query(Site).filter(Site.id == node.site_id, Site.project_id == project.id).one_or_none()
    if not site:
        raise Exception("Missing site with id {}.".format(node.site_id))
    new_config = set_value(new_config, 'ucpe:config.system:system.site', site.name)
    service = db.session.query(Service).filter(Service.id == site.service_id, Service.project_id == project.id).one_or_none()
    if not service:
        raise Exception("Missing service with id {}.".format(site.service_id))
    new_config = set_value(new_config, 'ucpe:config.system:system.service', service.name)
    customer = db.session.query(Customer).filter(Customer.id == service.customer_id, Customer.project_id == project.id).one_or_none()
    if not customer:
        raise Exception("Missing customer with id {}.".format(service.customer_id))
    new_config = set_value(new_config, 'ucpe:config.system:system.customer', customer.name)
    operator = db.session.query(Operator).filter(Operator.id == customer.operator_id, Operator.project_id == project.id).one_or_none()
    if not operator:
        raise Exception("Missing operator with id {}.".format(customer.operator_id))
    new_config = set_value(new_config, 'ucpe:config.system:system.operator', operator.name)
    if node.project_id != operator.project_id:
        raise Exception("Wrong project id for the node site.")
    hwtype = db.session.query(HWType).filter(HWType.id == node.hwtype_id, HWType.project_id == project.id).one_or_none()
    if not hwtype:
        raise Exception("Missing hwtype with id {}.".format(node.hwtype_id))
    new_config = set_value(new_config, 'ucpe:status.system:system.hwtype', hwtype.name)
    return new_config


# Save file in database. Use the full path. As file index is used the path!
def save_to_storage(config, project_id, file_name, file_index=None):
    if not os.path.exists(file_name):
        raise Exception("File '{}' does not exists.".format(file_name))
    if not file_index:
        file_index = os.path.abspath(file_name)
    db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
    project = db.session.query(Project).filter(Project.id == project_id).one_or_none()
    if not project:
        raise Exception("Project with id {} does not exists in database.".format(project_id))
    # Delete old storage
    db.session.query(Storage).filter(Storage.file_index == file_index, Storage.project_id == project.id).delete()
    db.session.commit()

    data = open(file_name, 'rb').read()
    chunk_total = len(data) // STORAGE_CHUNK_SIZE + 1
    if len(data) % STORAGE_CHUNK_SIZE > 0:
        chunk_total += 1
    chunk_count = 1
    for chunk_count in range(1, chunk_total):
        storage = Storage()
        storage.project_id = project.id
        storage.data = data[((chunk_count-1)*STORAGE_CHUNK_SIZE):(chunk_count*STORAGE_CHUNK_SIZE)]
        storage.file_index = file_index
        storage.file_name = os.path.basename(file_name)
        storage.chunk_num = chunk_count
        storage.chunk_total = chunk_total
        db.session.add(storage)
        db.session.commit()
    if len(data) % STORAGE_CHUNK_SIZE > 0:
        # Add last part
        storage = Storage()
        storage.project_id = project.id
        storage.data = data[(chunk_count*STORAGE_CHUNK_SIZE):]
        storage.file_index = file_index
        storage.file_name = os.path.basename(file_name)
        storage.chunk_num = chunk_count + 1
        storage.chunk_total = chunk_total
        db.session.add(storage)
        db.session.commit()
    return hashlib.sha256(data).hexdigest()


def load_from_storage(config, project_id, file_index):
    db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
    project = db.session.query(Project).filter(Project.id == project_id).one_or_none()
    if not project:
        raise Exception("Project with id {} does not exists in database.".format(project_id))
    storages = db.session.query(Storage).filter(Storage.file_index == file_index, Storage.project_id == project.id).order_by(Storage.chunk_num).all()
    data = b''
    chunk_num = 1
    file_name = None
    for storage in storages:
        file_name = storage.file_name
        if storage.chunk_num != chunk_num:
            raise Exception('Mess in storage data {}. Missing data chunk.'.format(file_index))
        if chunk_num > storage.chunk_total:
            raise Exception('Mess in storage data {}. Data chunks do not match the total.'.format(file_index))
        data += storage.data
        chunk_num += 1
    if not file_name:
        raise Exception('Data with index {} not found.'.format(file_index))
    return {'file_name': file_name, 'data': data}


def delete_storage(config, project_id, file_index):
    db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
    project = db.session.query(Project).filter(Project.id == project_id).one_or_none()
    if not project:
        raise Exception("Project with id {} does not exists in database.".format(project_id))
    db.session.query(Storage).filter(Storage.file_index == file_index, Storage.project_id == project.id).delete()
    db.session.commit()


# BULK OPERATIONS
def status_bulk_approve(config, uid_list, is_alarm=True):
    approved_list = []
    failed_list = []
    already_approved = []
    db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
    project_id = 1
    statuses = db.session.query(Status).filter(Status.uid.in_(uid_list)).all()
    for status in statuses:
        project_id = status.project_id
        if status.is_ignored:
            failed_list.append("Status for {} is blacklisted.".format(status.uid))
            continue
        if db.session.query(Node).filter(Node.uid == status.uid).count() > 0:
            already_approved.append(status.uid)
            continue
        # Check project
        if not status.project:
            failed_list.append("Missing project in the status for {}".format(status.uid))
            continue
        project = db.session.query(Project).filter(Project.name == status.project).one_or_none()
        if not project:
            failed_list.append("Project '{}' is missing from database for {}".format(status.project, status.uid))
            continue
        # Check operator
        if not status.operator:
            failed_list.append("Missing operator for {}".format(status.uid))
            continue
        operator = db.session.query(Operator).filter(
            Operator.project_id == project.id,
            Operator.name == status.operator
        ).one_or_none()
        if operator is None:
            failed_list.append("Operator '{}' is missing from database for {}".format(status.operator, status.uid))
            continue
        # Check customer
        if not status.customer:
            failed_list.append("Missing customer for {}".format(status.uid))
            continue
        customer = db.session.query(Customer).filter(
            Customer.project_id == project.id,
            Customer.operator_id == operator.id,
            Customer.name == status.customer
        ).one_or_none()
        if customer is None:
            failed_list.append("Customer '{}' is missing from database for {}".format(status.customer, status.uid))
            continue
        # Check service
        if not status.service:
            failed_list.append("Missing service for {}".format(status.uid))
            continue
        service = db.session.query(Service).filter(
            Service.project_id == project.id,
            Service.name == status.service,
            Service.customer_id == customer.id
        ).one_or_none()
        if service is None:
            failed_list.append("Service '{}' is missing from database for {}".format(status.service, status.uid))
            continue
        # Check site
        if not status.site:
            failed_list.append("Missing site in the status for {}".format(status.uid))
            continue
        site = db.session.query(Site).filter(
            Site.project_id == project.id,
            Site.name == status.site,
            Site.service_id == service.id
        ).one_or_none()
        if site is None:
            failed_list.append("Site '{}' is missing from database for {}".format(status.site, status.uid))
            continue
        hwtype = db.session.query(HWType).filter(
            HWType.project_id == project.id,
            HWType.name == status.hwtype
        ).one_or_none()
        if hwtype is None:
            failed_list.append("Hardware type '{}' is missing from database for {}".format(status.hwtype, status.uid))
            continue
        # Validation passes
        if db.session.query(Node).filter(Node.uid == status.uid).count() > 0:
            continue

        node = Node()
        node.uid = status.uid
        node.username = get_value(config, 'node.username', 'admin')
        node.password = get_value(config, 'node.password', 'Nfv@admin21')
        node.project_id = site.project_id
        node.site_id = site.id
        node.hwtype_id = hwtype.id
        node.admin_status = "wait for config"
        db.session.add(node)
        db.session.commit()
        db.session.flush()
        # Create config
        c = Config()
        c.node_id = node.id
        c.project_id = node.project_id
        c.uid = node.uid
        db.session.add(c)
        db.session.commit()
        db.session.flush()
        # Ask for configurations
        send_message(config, "manager:edge:{}".format(node.id), "get:config")
        # Try license
        if status.status == 'unlicensed' and get_value(config, 'auto_license'):
            send_message(config, "manager:edge:{}".format(node.id), "set:license")
        # Ask for applications
        if status.is_app_support:
            send_message(config, "manager:edge:{}".format(node.id), "apps:update")
        approved_list.append(str(status.uid))
    message = ""
    if len(approved_list) > 0:
        message = "Approved {}".format(', '.join(approved_list))
        send_notify(config, 0, "ucpe")
    if len(failed_list) > 0:
        if len(approved_list) > 0:
            message = message + "\n"
        message = "{}Failed {}".format(message, '\n'.join(failed_list))
    if not message and len(already_approved) > 0:
        message = "The nodes are already approved."
    if not message:
        message = "Nothing was approved. Please, check the list."
    if is_alarm:
        send_alarm(
            config,
            project_id=project_id,
            name='status_approved',
            type='system',
            severity='Info' if len(failed_list) == 0 else 'Critical',
            is_alarm=False,
            is_active=False if len(failed_list) == 0 else True,
            key='approve_node',
            value='Edge devices approve ' + ('completed' if len(failed_list) == 0 else 'failed'),
            description=message,
            corrective_action=''
        )
    if len(approved_list) == 0:
        return message, 403
    return message, 412 if len(failed_list) > 0 else 200


def controller_status_bulk_approve(config, hostname_list, is_alarm=True):
    approved_list = []
    failed_list = []
    already_approved = []
    db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
    project_id = 1
    statuses = db.session.query(ControllerStatus).filter(ControllerStatus.hostname.in_(hostname_list)).all()
    for status in statuses:
        project_id = status.project_id
        if db.session.query(Controller).filter(Controller.hostname == status.hostname).count() > 0:
            approved_list.append(status.hostname)
            continue
        # Check project
        if not status.project:
            failed_list.append("Missing project in the status for {}".format(status.hostname))
            continue
        project = db.session.query(Project).filter(Project.name == status.project).one_or_none()
        if not project:
            failed_list.append("Project '{}' is missing from database for {}".format(status.project, status.hostname))
            continue
        # Check operator
        if not status.operator:
            failed_list.append("Missing operator for {}".format(status.hostname))
            continue
        operator = db.session.query(Operator).filter(
            Operator.project_id == project.id,
            Operator.name == status.operator
        ).one_or_none()
        if operator is None:
            failed_list.append("Operator '{}' is missing from database for {}".format(status.operator, status.hostname))
            continue
        # Check customer
        if not status.customer:
            failed_list.append("Missing customer for {}".format(status.hostname))
            continue
        customer = db.session.query(Customer).filter(
            Customer.project_id == project.id,
            Customer.operator_id == operator.id,
            Customer.name == status.customer
        ).one_or_none()
        if customer is None:
            failed_list.append("Customer '{}' is missing from database for {}".format(status.customer, status.hostname))
            continue
        # Validation passes
        if db.session.query(Controller).filter(Controller.hostname == status.hostname).count() > 0:
            continue

        controller = Controller()
        controller.hostname = status.hostname
        controller.username = get_value(config, 'controller.username', 'admin')
        controller.password = get_value(config, 'controller.password', 'Nfv@admin21')
        controller.project_id = customer.project_id
        controller.customer_id = customer.id
        controller.is_local = False
        db.session.add(controller)
        db.session.commit()
        db.session.flush()
        approved_list.append(str(status.hostname))
    message = ""
    if len(approved_list) > 0:
        message = "Approved {}".format(', '.join(approved_list))
        send_notify(config, 0, "controller")
    if len(failed_list) > 0:
        if len(approved_list) > 0:
            message = message + "\n"
        message = "{}Failed {}".format(message, '\n'.join(failed_list))
    if not message and len(already_approved) > 0:
        message = "The controllers are already approved."
    if not message:
        message = "Nothing was approved. Please, check the list."
    if is_alarm:
        send_alarm(
            config,
            project_id=project_id,
            name='status_approved',
            type='system',
            severity='Info' if len(failed_list) == 0 else 'Critical',
            is_alarm=False,
            is_active=False if len(failed_list) == 0 else True,
            key='approve_controller',
            value='Controllers approve ' + ('completed' if len(failed_list) == 0 else 'failed'),
            description=message,
            corrective_action=''
        )
    if len(approved_list) == 0:
        return message, 403
    return message, 412 if len(failed_list) > 0 else 200


def node_bulk_delete(config, uid_list, is_alarm=True):
    if not uid_list:
        return
    db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
    nodes = db.session.query(Node).filter(Node.uid.in_(uid_list))
    nodes = nodes.all()
    project_node = {}
    for n in nodes:
        if not get_value(project_node, str(n.project_id)):
            project_node[str(n.project_id)] = []
        project_node[str(n.project_id)].append(str(n.uid))
        send_message(config, "manager:node:cache:delete:{}".format(n.uid), n.uid, ex=120)
        storage_list = []
        for v in db.session.query(Storage.id).filter(Storage.project_id == n.project_id,
                                                     Storage.file_index.like("/node/{}/%".format(n.id))).all():
            storage_list.append(v[0])
        if storage_list:
            delete_storage(config, n.project_id, "/node/{}/%".format(n.id))
        if n.is_cbox:
            controller = db.session.query(Controller).filter(Controller.project_id == n.project_id, Controller.hostname == n.hostname, Controller.is_local == True).one_or_none()
            if controller:
                db.delete_data_flow(Controller.__tablename__, controller.id)
        db.session.query(Event).filter(Event.type == 'node', Event.type_id == n.id).delete()
        db.session.query(Status).filter(Status.uid == n.uid, Status.status == 'unreachable').delete()
        db.session.commit()
        db.delete_data_flow(Node.__tablename__, n.id)
    for project_id, node_list in project_node.items():
        send_notify(config, project_id, 'ucpe')
        if is_alarm:
            send_alarm(
                config,
                project_id=project_id,
                name='node_deleted',
                type='system',
                severity='Info',
                is_alarm=False,
                is_active=False,
                key='delete',
                value='Nodes delete completed',
                description=', '.join(node_list),
                corrective_action=''
            )


def get_node_management_ip(config, uid, project_id):
    db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
    status = db.session.query(Status).filter(Status.uid == uid, Status.project_id == project_id).one_or_none()
    if not status:
        raise Exception("Device with serial number '{}' does not have status.".format(uid))
    data = json.loads(status.data)
    management_ip = None
    for val in get_value(data, 'management'):
        if get_value(val, 'status') != 'up':
            continue
        ip = get_value(val, 'ipv4-address')
        if ip and is_alive(ip, port=7373):
            if not management_ip or get_value(val, 'name') == 'tun0':
                management_ip = ip
            continue
        ip = get_value(val, 'ipv6-address')
        if ip and is_alive(ip, port=7373):
            if not management_ip or get_value(val, 'name') == 'tun0':
                management_ip = ip
            continue
    if management_ip:
        return management_ip
    raise Exception("No UP management interfaces found for device with serial number '{}'.".format(uid))


def get_controller_management_ip(config, hostname, project_id, is_local=False):
    db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
    if not is_local:
        status = db.session.query(ControllerStatus).filter(ControllerStatus.hostname == hostname, ControllerStatus.project_id == project_id).one_or_none()
        if not status:
            raise Exception("Controller '{}' does not have status.".format(hostname))
        data = json.loads(status.data)
        management_ip = None
        for val in get_value(data, 'management'):
            if get_value(val, 'status') != 'up':
                continue
            ip = get_value(val, 'ipv4-address')
            if ip and is_alive(ip, port=7373):
                if not management_ip or get_value(val, 'name') == 'tun0':
                    management_ip = ip
                continue
            ip = get_value(val, 'ipv6-address')
            if ip and is_alive(ip, port=7373):
                if not management_ip or get_value(val, 'name') == 'tun0':
                    management_ip = ip
                continue
        if management_ip:
            return management_ip
    else:
        node = db.session.query(Node).filter(Node.hostname == hostname, Node.project_id == project_id).one_or_none()
        if node.is_cbox and node.hostname:
            return get_node_management_ip(config, node.uid, node.project_id)
    raise Exception("No UP management interfaces found for controller '{}'.".format(hostname))


def controller_bulk_delete(config, hostname_list, is_alarm=True):
    db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
    controllers = db.session.query(Controller).filter(Controller.hostname.in_(hostname_list))
    controllers = controllers.all()
    project_controller = {}
    for c in controllers:
        # try:
        #     # Remove console NAT definitions if such
        #     controller_ip = get_controller_management_ip(config, c.hostname)
        #     for line in execute_shell_command("sudo -S iptables -S -t nat | grep \"{}\"".format(controller_ip)).split('\n'):
        #         del_str = line.replace('-A PREROUTING', '-D PREROUTING')
        #         execute_shell_command("sudo -S iptables -t nat {}".format(del_str))
        # except Exception as ex:
        #     logger.error(ex)
        if c.is_local:
            continue
        if not get_value(project_controller, str(c.project_id)):
            project_controller[str(c.project_id)] = []
        project_controller[str(c.project_id)].append(str(c.hostname))

        db.session.query(Event).filter(Event.type == 'controller', Event.type_id == c.id).delete()
        db.session.query(ControllerStatus).filter(ControllerStatus.hostname == c.hostname, ControllerStatus.status == 'unreachable').delete()
        db.session.commit()
        db.delete_data_flow(Controller.__tablename__, c.id)
    for project_id, controller_list in project_controller.items():
        send_notify(config, project_id, 'controller')
        if is_alarm:
            send_alarm(
                config,
                project_id=project_id,
                name='controller_deleted',
                type='system',
                severity='Info',
                is_alarm=False,
                is_active=False,
                key='delete',
                value='Controllers delete completed',
                description=', '.join(controller_list),
                corrective_action=''
            )


def send_alarm(
        config,
        project_id,
        name,
        type='system',
        type_id=0,
        severity='Info',
        is_alarm=True,
        is_active=True,
        key='',
        value='',
        description='',
        corrective_action=''
):
    data = {
        'project_id': project_id,
        'update_time': datetime.now(timezone.utc).timestamp(),
        'name': name,
        'type': type,
        'type_id': type_id,
        'severity': severity,
        'is_alarm': is_alarm,
        'is_active': is_active,
        'key': key,
        'value': value,
        'description': description,
        'corrective_action': corrective_action
    }
    # send_message(config, "manager:alarm:{}:{}:{}".format(type, type_id, datetime.now(timezone.utc).timestamp()), json.dumps(event_data))
    db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
    if get_value(data, 'type') == 'node':
        project = db.session.query(Project).filter(Project.id == get_value(data, 'project_id', 0)).one_or_none()
        if not project:
            logger.warning("Project {} not found in database. Skipping the alarm handling.".format(get_value(data, 'project_id')))
            return
        node = db.session.query(Node).filter(Node.id == get_value(data, 'type_id', 0), Node.project_id == project.id).one_or_none()
        if not node:
            logger.warning("Node {} not found in database. Skipping the alarm handling.".format(get_value(data, 'type_id')))
            return
    severity_id = -1
    for k, v in severity_type.items():
        if v == get_value(data, 'severity'):
            severity_id = k
            break
    if severity_id == -1:
        logger.warning("Unknown severity '{}' for alarm. {}".format(get_value(data, 'severity'), value))
        return
    data['severity_id'] = severity_id
    data.pop('severity')
    data['update_time'] = datetime.utcfromtimestamp(data['update_time'])

    # Check if it is already registered
    event = db.session.query(Event).filter(
        Event.project_id == data['project_id'],
        Event.update_time == data['update_time'],
        Event.name == data['name'],
        Event.key == data['key'],
        Event.value == data['value'],
        Event.type == data['type'],
        Event.type_id == data['type_id']
    )
    if event.count() > 0:
        logger.warn('The event is already registered: {}'.format(data))
        return
    data['key'] = data['key'][:50]
    data['value'] = data['value'][:50]
    db.session.add(Event(**data))
    db.session.commit()
    send_notify(config, data['project_id'], 'event')
    logger.info('Created new alarm: {}'.format(data))


def validate_manager_config(config, cred, manager_config, id=None):
    project = None
    user = None
    db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
    if not get_value(cred, 'is_super_user'):
        project = db.session.query(Project).filter(Project.name == get_value(cred, 'project')).one_or_none()
        if not project:
            return "Project '{}' does not exists.".format(get_value(cred, 'project')), 404
        user = db.get_user(cred)

    device_schema = None
    if id:
        node = db.session.query(Node).filter(Node.id == id).one_or_none()
        if not node:
            return "Node with id {} does not exists.".format(id), 404
        node_config = db.session.query(Config).filter(Config.node_id == id).one_or_none()
        if node_config is None:
            return "This node config does not exists.", 404
        if node_config and node_config.device_schema and 'properties' in node_config.device_schema:
            device_schema = json.loads(node_config.device_schema)
            # if node_config.schema_version > get_value(config, 'config_schema', 0):
            #     return "This node configuration schema is not supported! Please, upgrade the manager.", 404
        project = db.session.query(Project).filter(Project.id == node.project_id).one_or_none()

        # Check for deployed service in case of changed controller
        old_manager_config = json.loads(node_config.manager_config)
        old_is_cbox = get_value(old_manager_config, 'ucpe:config.kubernetes:kubernetes.cbox.enabled', False)
        old_controller_id = get_value(old_manager_config, 'ucpe:config.system:system.hostname')
        new_is_cbox = get_value(manager_config, 'ucpe:config.kubernetes:kubernetes.cbox.enabled', False)
        new_controller_id = get_value(manager_config, 'ucpe:config.system:system.hostname')
        if old_is_cbox != new_is_cbox or old_controller_id != new_controller_id:
            if db.session.query(KubService).filter(KubService.node_id == node.id).count() > 0:
                return "This node contains deployed services. Please, delete the services before changing the controller settings.", 403

    if not device_schema:
        schema_file = '/etc/manager/default_schema.json'
        if not os.path.exists(schema_file):
            return "Missing default device schema.", 404
        with open(schema_file, 'r') as file:
            device_schema = json.loads(file.read().replace("\\\\p{N}\\\\p{L}", "0-9A-z"))
            # device_schema = json.load(file)

    validation_errors = []
    hostname = get_value(manager_config, 'ucpe:config.system:system.hostname')
    if not is_valid_hostname(hostname):
        validation_errors.append("Invalid hostname '{}'.".format(hostname))
    # Validate manager configuration
    netconf_addr = get_value(manager_config, 'ietf-netconf-server:netconf-server.listen.endpoint.ssh.address')
    if netconf_addr and not ipv4(netconf_addr) and not ipv6(netconf_addr):
        validation_errors.append("Invalid NetConf server address '{}'.".format(netconf_addr))

    if get_value(manager_config, 'ucpe:config.dhcprelay:dhcp-relay.enabled', False):
        dhcp_relay_server = get_value(manager_config, 'ucpe:config.dhcprelay:dhcp-relay.dhcp-relay-server')
        if dhcp_relay_server and not ipv4(dhcp_relay_server) and not ipv6(dhcp_relay_server) and len(dhcp_relay_server) == 0:
            validation_errors.append("Invalid DHCP relay server '{}'.".format(dhcp_relay_server))

    if get_value(manager_config, 'ucpe:config.snmp-server:snmp-server.enable', False):
        snmp_server_address = get_value(manager_config, 'ucpe:config.snmp-server:snmp-server.bind-address')
        if snmp_server_address and not ipv4(snmp_server_address) and not ipv6(snmp_server_address):
            validation_errors.append("Invalid DHCP server bind address '{}'.".format(snmp_server_address))
        # for target in get_value(manager_config, 'ucpe:config.snmp-server:snmp-server.target-address', []):
        #     if get_value(target, "enable", False):
        #         dst_addr = get_value(target, "dst-address")
        #         if not ipv4(dst_addr) and not ipv6(dst_addr) and len(dst_addr) == 0:
        #             validation_errors.append("Invalid SNMP target address '{}' for target {}.".format(dst_addr, get_value(target, "id")))

    if get_value(manager_config, 'ucpe:config.security:security.cli-whitelist.enabled', False):
        for v in get_value(manager_config, 'ucpe:config.security:security.cli-whitelist.access-source-ip', []):
            if not v:
                continue
            addr = get_value(v, 'address')
            if addr and not ipv4(addr) and not ipv6(addr):
                validation_errors.append("Invalid CLI whitelist address '{}'.".format(addr))

    # for target in get_value(manager_config, 'ucpe:config.syslog:syslog.remote-servers', []):
    #     if get_value(target, "enable", False):
    #         srv_addr = get_value(target, "ip-address")
    #         if not ipv4(srv_addr) and not ipv6(srv_addr) and len(srv_addr) == 0:
    #             validation_errors.append("Invalid Syslog server address '{}' for server {}.".format(srv_addr, get_value(target, "id")))

    metrics = {}
    for interface in get_value(manager_config, 'ucpe:config.interfaces:interface'):
        # Add patch for ipv4-prefix mask
        ip_v4 = get_value(interface, 'ipv4-prefix')
        name = get_value(interface, 'name')
        if ip_v4 and not ipv4_cidr(ip_v4):
            validation_errors.append("Invalid IPv4 address '{}' for interface {}.".format(ip_v4, name))
        ip_v6 = get_value(interface, 'ipv6-prefix')
        if ip_v6 and not ipv6_cidr(ip_v6):
            validation_errors.append("Invalid IPv6 address '{}' for interface {}.".format(ip_v6, name))

        # Check DNS and Gateway
        dns = get_value(interface, 'dns')
        gateway = get_value(interface, 'gateway')
        if dns and not ipv4(dns):
            validation_errors.append("Invalid dns '{}' for interface {}.".format(dns, name))
        if gateway and not ipv4(gateway):
            validation_errors.append("Invalid gateway '{}' for interface {}.".format(gateway, name))
        dns = get_value(interface, 'dns6')
        gateway = get_value(interface, 'gateway6')
        if dns and not ipv6(dns):
            validation_errors.append("Invalid dns '{}' for interface {}.".format(dns, name))
        if gateway and not ipv6(gateway):
            validation_errors.append("Invalid gateway '{}' for interface {}.".format(gateway, name))

        # Add patch for management interfaces metric
        is_management = get_value(interface, 'management', False)
        if is_management:
            is_enable = get_value(interface, 'enable', True)
            if not is_enable:
                continue
            metric = get_value(interface, 'metric')
            if metric is not None:
                for k, v in metrics.items():
                    if v == metric:
                        validation_errors.append("Interface {} has equal metric {} with {}. Management interfaces must have different metrics.".format(name, metric, k))
                        break
                metrics[name] = metric
    if len(metrics) == 0:   # Management metrics
        validation_errors.append("This configuration does not have any management interface.")

    if len(validation_errors) == 0:
        for error in sorted(Draft4Validator(device_schema).iter_errors(manager_config), key=lambda e: e.path):
            err_path = []
            for v in error.path:
                err_path.append(str(v))
            validation_errors.append("Configuration error in '{}': {}".format('.'.join(err_path), error.message))
            logger.error(error)

    if len(validation_errors):
        return "\n".join(validation_errors), 403

    new_hwtype = get_value(manager_config, 'ucpe:status.system:system.hwtype')
    new_hostname = get_value(manager_config, 'ucpe:config.system:system.hostname')
    if not is_valid_hostname(new_hostname):
        return "Invalid hostname '{}'.".format(hostname), 403
    if db.session.query(Node).filter(Node.id != id, Node.hostname == new_hostname).one_or_none():
        return "There is another node with same hostname.", 403
    if db.session.query(Controller).filter(Controller.hostname == new_hostname, Controller.is_local == False).one_or_none():
        return "There is controller with same hostname.", 403
    project_name = get_value(manager_config, 'ucpe:config.system:system.project')
    if project_name:
        new_project = db.session.query(Project).filter(Project.name == project_name).one_or_none()
        if not new_project:
            return "There is not project with name '{}'.".format(project_name), 403
        if not get_value(cred, 'is_super_user') and new_project.id != project.id:
            return "Changing the project to '{}' is not allowed.".format(project_name), 403
        project = new_project

    operator_name = get_value(manager_config, 'ucpe:config.system:system.operator')
    if operator_name:
        operator = db.session.query(Operator).filter(Operator.project_id == project.id, Operator.name == operator_name).one_or_none()
        if not operator:
            return "There is not operator with name '{}'.".format(operator_name), 403
        if user and user.group_id >= 1 and user.operator_id and user.operator_id != operator.id:
            return "Changing operator name is not allowed.", 403
    customer_name = get_value(manager_config, 'ucpe:config.system:system.customer')
    if customer_name:
        customer = db.session.query(Customer).filter(Customer.project_id == project.id, Customer.name == customer_name).one_or_none()
        if not customer:
            return "There is not customer with name '{}'.".format(customer_name), 403
        if user and user.group_id >= 2 and user.customer_id and user.customer_id != customer.id:
            return "Changing customer name is not allowed.", 403
    service_name = get_value(manager_config, 'ucpe:config.system:system.service')
    if service_name:
        if not db.session.query(Service).filter(Service.project_id == project.id, Service.name == service_name).one_or_none():
            return "There is not service with name '{}'.".format(service_name), 403
    site_name = get_value(manager_config, 'ucpe:config.system:system.site')
    if site_name:
        site = db.session.query(Site).filter(Site.project_id == project.id, Site.name == site_name).one_or_none()
        if not site:
            return "There is not site with name '{}'.".format(site_name), 403
    hwtype = db.session.query(HWType).filter(HWType.project_id == project.id, HWType.name == new_hwtype).one_or_none()
    if hwtype is None:
        return "Missing hardware type '{}'.".format(new_hwtype), 403
    controller_name = get_value(manager_config, 'ucpe:config.kubernetes:kubernetes.controller')
    if controller_name:
        controller_hostname = db.session.query(Controller).filter(Controller.project_id == project.id, Controller.hostname == controller_name).one_or_none()
        if not controller_hostname:
            controller_ip = db.session.query(ControllerStatus).filter(ControllerStatus.management_ips.regexp_match(controller_name + "($|,)")).one_or_none()
            if not controller_ip:
                if ipv4(controller_name) or ipv6(controller_name):
                    return "There is not controller with ip '{}'.".format(controller_name), 403
                else:
                    return "There is not controller with hostname '{}'.".format(controller_name), 403
