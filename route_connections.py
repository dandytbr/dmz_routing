"""
This flask application accepts the requests from a destination and routes it to
a destination. This app is supposed to be running in the background in the DMZ
node set up.
"""
import django_yamlconf
import json
import logging
import logging.handlers
import requests

from flask import Flask, request, jsonify
from werkzeug.exceptions import HTTPException
from urllib3.exceptions import InsecureRequestWarning

app = Flask(__name__)
settings = None
OK = 200

class Settings:
    """
    Settings controlling the applicataion with production values.
    """
    def __init__(self):
        self.DEST_URL = "YAMLCONF Defined"
        self.DEST_HEADER = "YAMLCONF Defined"
        self.LOGFILE = "YAMLCONF Defined"
        self.BIND_ADDR = "YAMLCONF Defined"
        self.ENV = "YAMLCONF Defined"

@app.errorhandler(Exception)
def errorhandler(e):
    """
    Default error handler for various exceptions encountered.
    """
    client_ip = None
    code = 500
    if isinstance(e, HTTPException):
        code = e.code
        client_ip = str(request.remote_addr)
        logger.error("Error encountered from IP %s : %s", client_ip, str(e))
    return jsonify(error=str(e), code=str(code))


@app.route('/api/v1/route', methods=['POST'])
def route_handler():
    """
    This function accepts the incoming connections from external IPs to the API
    and performs basic data processing.
    """
    data = request.get_json()
    source_addr = str(request.remote_addr)
    logger.info("Data received from external IP %s : %s", source_addr, str(data))
    logger.info("Data routed to destination IP %s., ")
    route_data(data, source_addr)

    return '1'


def route_data(data, remote_addr):

    url = settings.DEST_URL

    # Supress the urllib3 warnings for certificate verification
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    r = requests.post(url, data=json.dumps(data), headers=settings.DEST_HEADER, verify=False)
    if r.status_code == OK:
        logger.info("Data successfully posted to stackstorm from remote IP %s.",
                    remote_addr)
    else:
        logger.error("%s : Failed to post data to stackstorm from remote IP %s.",
                     str(r.status_code), remote_addr)

if __name__ == "__main__":
    settings = Settings()
    django_yamlconf.load(settings=settings, project="route_connections")

    # Setup and configure rotating logging mechanism
    handler = logging.handlers.RotatingFileHandler(
        settings.LOGFILE,
        maxBytes=10 * 1024 ** 2,  # 10MB chunks of logs
        backupCount=10  # 100MB of total logs
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    )
    logger = logging.getLogger('dmzlogger')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)

    app.run(host=settings.BIND_ADDR)
