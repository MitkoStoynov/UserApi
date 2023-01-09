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

from manager.orm import *

CONFIG_FILE = '/etc/manager/edge.yml'

config = {}


def exception_handler(error):
    logger.exception(error)
    return str(error), 500


def event_stream(project_id, entry):
    redis_srv = redis.Redis(host=get_value(config, 'redis.host'),
                            password=get_value(config, 'redis.password'),
                            port=int(get_value(config, 'redis.port', 6378)),
                            socket_timeout=300,
                            socket_connect_timeout=300
                            )
    pubsub = redis_srv.pubsub()
    channels = []
    if project_id == '0':
        db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
        for v in db.session.query(Project.id).all():
            channels.append('{}.{}'.format(entry, v[0]))
    else:
        channels.append('{}.{}'.format(entry, project_id))
    pubsub.subscribe(*channels)
    for message in pubsub.listen():
        if message['type'] == 'message':
            yield 'data: %s\n\n' % message['data'].decode('utf-8')


def start_app(conf_file, run_server=False):
    global logger, config

    if not os.path.exists(conf_file):
        print('Missing config file {}'.format(conf_file))
        exit(1)

    with open(CONFIG_FILE, 'r') as file:
        config = yaml.load(file, Loader=yaml.FullLoader)

    # Logging configuration
    logger.setLevel(get_value(config, 'log.level', 'INFO').upper())
    log_folder = get_value(config, 'log.folder')
    if log_folder:
        os.makedirs(log_folder, exist_ok=True)
        log_file = log_folder + '/api.log'
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logFormatter)
        logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logFormatter)
    logger.addHandler(console_handler)

    os.environ['edge_config'] = json.dumps(config)

    app = connexion.FlaskApp(__name__, debug=logger.level == logging.DEBUG, options={"swagger_ui": get_value(config, 'api.swagger', True)})
    CORS(app.app)
    app.add_api(get_value(config, 'api.openapi', '/etc/manager/openapi.yml'), resolver=RestyResolver(get_value(config, 'api.prefix', 'api')))
    app.add_error_handler(Exception, exception_handler)

    @app.route('/notify/<project_id>/<entry>', methods=['GET'])
    def get_notify(project_id, entry):
        return Response(event_stream(project_id, entry), mimetype="text/event-stream",
                        headers={'Access-Control-Allow-Origin': '*'})

    # @app.app.before_request
    # def before_request():
    #     method = "{}{}".format(str(request.method).lower(), request.endpoint)
    #     if request.method == 'POST' and \
    #             (not request.json or (request.json and get_value(request.json, 'filter', None) is None)) \
    #             and not book_operation(config, method):
    #         return "There is already started operation! Please, retry later.", 503
    #
    # @app.app.after_request
    # def after_request(response):
    #     if request.method == 'POST':
    #         delete_message(config, "{}{}".format(str(request.method).lower(), request.endpoint))
    #     return response

    try:
        db = ManagerDB(get_value(config, 'database_engine'), logger.level == logging.DEBUG)
        db.initialize_database(config=config)
        db.session.query(Node).limit(1).all()
    except Exception as ex:
        logger.error(ex)
        exit(0)

    if not run_server:
        return app

    api_host = get_value(config, 'api.host', '127.0.0.1')
    api_port = get_value(config, 'api.port', 5001)
    logger.info("Start Manager API at https://{}:{}".format(api_host, api_port))

    # Debug
    app.run(
        host=api_host,
        port=api_port,
        debug=logger.level == logging.DEBUG,
        ssl_context=(get_value(config, 'ssl.certfile'), get_value(config, 'ssl.keyfile'))
    )

    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Manager API',
                                     epilog='Example: {} --config'.format(sys.argv[0]))
    parser.add_argument('--config', help='Configuration file', required=True)
    args = parser.parse_args()
    if args.config:
        CONFIG_FILE = args.config
    start_app(CONFIG_FILE, True)
else:
    application = start_app(CONFIG_FILE)
