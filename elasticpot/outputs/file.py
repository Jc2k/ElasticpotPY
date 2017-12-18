import json


class Output(object):

    def __init__(self, config):
        self._outputfile = open(config['jsonpath'], 'a')

    def send(self, event):
        self._outputfile.write(json.dumps(event) + '\n')
