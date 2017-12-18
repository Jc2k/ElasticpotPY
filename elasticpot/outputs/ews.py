import os
from urllib.parse import quote
import logging

import requests


logger = logging.getLogger('elasticpot.outputs.ews')

EWS_TXT_PATH = os.path.join(os.path.dirname(__file__), '../templates/ews.txt')
with open(EWS_TXT_PATH, 'r') as fp:
    EWS_TXT = fp.read()


class Output(object):

    def __init__(self, config):
        self.config = config
        self.enabled = config.get('enable')

    def send(self, event):
        xml = EWS_TXT.replace('_IP_', event['src_ip'])
        xml = xml.replace('_TARGET_', event['dest_ip'])
        xml = xml.replace('_SRCPORT_', str(event['src_port']))
        xml = xml.replace('_DSTPORT_', str(event['dest_port']))
        xml = xml.replace('_USERNAME_', self.config['username'])
        xml = xml.replace('_TOKEN_', self.config['token'])
        xml = xml.replace('_URL_', quote(str(self.config['rhost_first'])))
        xml = xml.replace('_RAW_', event['raw'])
        xml = xml.replace('_DATA_', quote(str(event['postdata'])))
        xml = xml.replace('_NODEID_', self.config['elasticpot']['nodeid'])

        xml = xml.replace('_TIME_', event['timestamp'])

        headers = {'Content-Type': 'application/xml'}

        # fix ignorecert to verifycert logic

        ignorecert = self.config.get('ignorecert', '')
        if (ignorecert is None):
            ignorecert = True
        elif (ignorecert == 'true'):
            ignorecert = False
        elif (ignorecert == 'false'):
            ignorecert = True

        try:
            requests.post(
                self.config['rhost_first'],
                data=xml,
                headers=headers,
                verify=ignorecert,
                timeout=5,
            )
        except requests.exceptions.Timeout:
            logger.error(
                'Elasticpot: Error trying to submit attack: Connection timeout'
            )
        except requests.exceptions.RequestException as e:
            logger.exeception('Unhandled EWS exception')
