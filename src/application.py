#!/usr/bin/env python

import os
import sys

sys.path.append(os.path.dirname(__name__))

import app
from app import utils
from app.config import (DEBUG, DEBUGGER, LISTEN_ADDR, PORT, THREADED)
from werkzeug.serving import WSGIRequestHandler


# create an app instance
application = app.create_app()
application.debug = DEBUGGER

# set HTTP/1.1
WSGIRequestHandler.protocol_version = 'HTTP/1.1'

for code in range(400, 451):
    try:
        application.errorhandler(code)(utils.error_handler)
    except KeyError:
        pass
    
for code in range(500, 511):
    try:
        application.errorhandler(code)(utils.error_handler)
    except KeyError:
        pass

application.errorhandler(404)(utils.error_handler)


if __name__ == '__main__':
    application.run(
        threaded=THREADED,
        debug=DEBUG,
        host=LISTEN_ADDR,
        port=PORT
    )
