import connexion
from flask_sqlalchemy import SQLAlchemy


# JWT
path = './jwtRSA256-public.pem'
file = open(path, 'r')
private_path = './jwtRSA256-private.pem'
private_file = open(private_path, 'r')
private_key = private_file.read()
public_key = file.read()
private_file.close()
file.close()


# SQLAlchemy object
db = SQLAlchemy()

# Flask object
app = connexion.FlaskApp("ServerMonitoringApi", debug=True)


app.add_api('swagger.yml')
application = app.app
application.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:bjhv@localhost/diploma'
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db.init_app(application)
