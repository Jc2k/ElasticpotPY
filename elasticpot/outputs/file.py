import json

from bottle import request


class Output(object):

    def __init__(self, config):
        self._outputfile = open(config['jsonpath'], 'a')

    def send(self, event):
        data = {}
        data['timestamp'] = event['timestamp']
        data['event_type'] = 'alert'
        data['src_ip'] = event['src_ip']
        data['src_port'] = event['src_port']
        data['dest_ip'] = event['dest_ip']
        data['dest_port'] = event['dest_port']

        data['honeypot'] = {
            'name': 'Elasticpot',
            'nodeid': request.app.config['elasticpot']['nodeid'],
            'query': event['querystring'],
            'postdata': event['body'],
            'raw': event['raw'],
        }

        self._outputfile.write(json.dumps(event) + '\n')
