from bottle import route, run, request, response, error, default_app, hook
import requests
import os
import configparser
import base64
import datetime
import ipaddress
import urllib.request
import json


##########################
# Config section
##########################

configfile = "elasticpot.cfg"   # point to elasticpot.cfg or an ews.cfg if you use ewsposter


def readConfig():
    config = configparser.ConfigParser()

    config['main'] = {
        'ip': '127.0.0.1',
    }

    config['elasticpot'] = {
        'nodeid': 'elasticpot-community-1',
        'elasticpot': 'True',
    }

    config['output_console'] = {
        'enabled': 'True',
    }

    config['output_ews'] = {
        'enabled': 'False',
        'username': '',
        'token': '',
        'rhost_first': '',
        'ignorecert': 'False',
    }

    config['output_file'] = {
        'enabled': 'False',
        'logfile': 'elasticpot.log',
    }

    config['output_hpfeeds'] = {
        'enabled': 'False',
        'host': 'localhost',
        'port': '',
        'ident': '',
        'secret': '',
        'channel': 'elasticpot',
    }

    if os.path.exists(configfile):
        config.read(configfile)

    for section in config.sections():
        for key in config[section].keys():
            envkey = '{}_{}'.format(section, key).upper()
            if envkey in os.environ:
                print("Setting {}.{} from environment".format(section, key))
                config[section][key] = os.environ[envkey]

    if not config['main']['ip'] or not ipaddress.ip_address(config['main']['ip']).is_private:
        host_ip = requests.get('https://ifconfig.co/json').json()['ip']
        print("Elasticpot: IP in config file is private. Determined the public IP %s" % host_ip)
        config['main']['ip'] = host_ip

    return config
