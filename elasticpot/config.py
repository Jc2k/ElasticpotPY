import requests
import os
import configparser
import ipaddress
import logging

logger = logging.getLogger('elasticpot.wsgi')

configfile = "elasticpot.cfg"


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
                logger.debug(
                    "Setting {}.{} from environment".format(section, key)
                )
                config[section][key] = os.environ[envkey]

    fetch_external_ip = False
    if not config['main']['ip']:
        fetch_external_ip = True
    else:
        try:
            address = ipaddress.ip_address(config['main']['ip'])
            fetch_external_ip = address.is_private
        except ValueError:
            fetch_external_ip = True

    if fetch_external_ip:
        host_ip = requests.get('https://ifconfig.co/json').json()['ip']
        logger.debug('Fetched external IP: {}'.format(host_ip))
        config['main']['ip'] = host_ip

    return config
