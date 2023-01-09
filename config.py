import connexion
from api import *
from orm import Database

# JWT
path = 'cert/jwtRSA256-public.pem'
file = open(path, 'r')
private_path = 'cert/jwtRSA256-private.pem'
private_file = open(private_path, 'r')
private_key = private_file.read()
public_key = file.read()
private_file.close()
file.close()

# Flask object
app = connexion.FlaskApp("ServerMonitoringApi", debug=True)

app.add_api('openapi.yml')
db = Database()
