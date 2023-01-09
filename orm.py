from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey, UniqueConstraint, MetaData, asc, desc, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from werkzeug.security import generate_password_hash

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
    name = Column(String(100), nullable=False, unique=True)
    email = Column(String(100), nullable=False, unique=True)
    password = Column(String(255), nullable=False)
    description = Column("description", String(255), default='')
    role_id = Column(Integer, ForeignKey('role.id'))
    project_id = Column(Integer, ForeignKey('project.id'))
    __table_args__ = (UniqueConstraint('project_id', 'name', name='_user_uc'),)


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
        return

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
        super_user.email = 'admin@admin'
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


db = Database()
db.initialize_database()