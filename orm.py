import json

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey, UniqueConstraint, MetaData, asc, desc, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash

from utils import get_value

DATABASE_URI = 'mysql+mysqlconnector://root:bjhv@localhost:3306'

Base = declarative_base()


class Role(Base):
    __tablename__ = "role"
    id = Column(Integer, primary_key=True)
    role = Column("name", String(50), default='')


class Project(Base):
    __tablename__ = "project"
    id = Column(Integer, primary_key=True)
    name = Column("name", String(50), default='')
    description = Column("description", String(255), default='')
    __table_args__ = (UniqueConstraint('name', name='_project_uc'),)


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    username = Column(String(100), nullable=False)
    password = Column(String(255), nullable=False)
    description = Column("description", String(255), default='')
    role_id = Column(Integer, ForeignKey('role.id'))
    project_id = Column(Integer, ForeignKey('project.id'))
    # __table_args__ = (UniqueConstraint('project_id', 'name', name='_user_uc'),)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Database:
    def __init__(self, DATABASE_URI=DATABASE_URI):
        # Create the database if it does not exist
        engine = create_engine(DATABASE_URI)
        engine.execute("CREATE DATABASE IF NOT EXISTS diploma")
        # Connect to the database
        DATABASE_URI = 'mysql+mysqlconnector://root:bjhv@localhost:3306/diploma'
        self.engine = create_engine(DATABASE_URI)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()

    def get_user(self, cred):
        project = self.session.query(Project).filter(Project.name == cred['project']).one_or_none()
        if not project:
            raise Exception("Project '{}' not found in database.".format(cred['project']))
        user = self.session.query(User).filter(User.username == cred['username'],
                                               User.project_id == project.id).one_or_none()
        if not user:
            raise Exception("User '{}' not found in database.".format(cred['username']))
        return user

    def get_dependencies_list(self, table_name, id, exclude_list=[]):
        use_list = []
        db_name = "diploma"
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

    def delete_data_flow(self, table_name, id, exclude_list=[]):
        for val in self.get_dependencies_list(table_name, id, exclude_list):
            data = self.session.execute("SELECT ID FROM {} WHERE {}={}".format(val['table'], val['field'], id))
            for row in data:
                self.delete_data_flow(val['table'], row[0], exclude_list=exclude_list)

        self.session.execute("DELETE FROM {} WHERE ID={}".format(table_name, id))
        self.session.commit()

    def add_roles(self):
        roles = [
            Role(role="Administrator"),
            Role(role="Operator"),
            Role(role="Customer")
        ]
        self.session.bulk_save_objects(roles)
        self.session.commit()

    def add_super_user(self):
        super_user = User()
        super_user.id = 1
        super_user.project_id = 1
        super_user.name = 'admin'
        super_user.username = 'admin@admin'
        super_user.password = generate_password_hash('Mmsadmin@181')
        super_user.description = 'System administrator administrative account'
        self.session.add(super_user)
        self.session.commit()

    def add_super_project(self):
        super_project = Project()
        super_project.id = 1
        super_project.name = 'uktc.bg'
        super_project.description = "default project"
        self.session.add(super_project)
        self.session.commit()

    def initialize_database(self):
        m = MetaData()
        m.reflect(self.engine)
        tables = m.tables.keys()
        print(tables)
        Base.metadata.create_all(bind=self.engine)
        if 'project' not in tables:
            self.add_super_project()
        if 'user' not in tables:
            self.add_super_user()
        if 'role' not in tables:
            self.add_roles()


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