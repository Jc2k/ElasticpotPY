import logging

from bottle import default_app

from .config import readConfig
from .outputs import Outputter
from . import views
del views

logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)

application = default_app()
application.config = readConfig()
application.outputs = Outputter(application.config)
