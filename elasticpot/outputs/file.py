import json


class Output(object):
        
    def __init__(self, config):
        self.enabled = config.get('enabled', 'false').lower() in ('1', 'true', 'yes')
        if self.enabled:
            self._outputfile = open(config['jsonpath'], 'a')

    def send(self, event):
        self._outputfile.write(json.dumps(event) + '\n')
