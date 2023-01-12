import os
import sys

import requests
import yaml
import argparse
import connexion
from connexion.resolver import RestyResolver
from flask import Response
from flask import request
from flask_cors import CORS
from requests import get

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from utils import *
from orm import *

CONFIG_FILE = 'monitor.yml'

config = {}


def start_app(conf_file, run_server=False):
    global config

    if not os.path.exists(conf_file):
        print('Missing config file {}'.format(conf_file))
        exit(1)

    with open(CONFIG_FILE, 'r') as file:
        config = yaml.load(file, Loader=yaml.FullLoader)

    os.environ['monitor'] = json.dumps(config)

    app = connexion.FlaskApp(__name__, options={"swagger_ui": get_value(config, 'api.swagger', True)})
    CORS(app.app)
    app.add_api(get_value(config, 'api.openapi', 'openapi.yml'), resolver=RestyResolver(get_value(config, 'api.prefix', 'api')))

    try:
        db = Database()
        db.initialize_database()
    except Exception as ex:
        exit(0)

    if not run_server:
        return app

    api_host = get_value(config, 'api.host', '127.0.0.1')
    api_port = get_value(config, 'api.port', 5001)

    # Debug
    app.run(
        host=api_host,
        port=api_port,
        debug=True
        # ssl_context=(get_value(config, 'ssl.certfile'), get_value(config, 'ssl.keyfile'))
    )

    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Monitor API',
                                     epilog='Example: {} --config'.format(sys.argv[0]))
    parser.add_argument('--config', help='Configuration file', required=True)
    args = parser.parse_args()
    if args.config:
        CONFIG_FILE = args.config
    start_app(CONFIG_FILE, True)
else:
    application = start_app(CONFIG_FILE)
