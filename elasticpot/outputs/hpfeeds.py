import json

import hpfeeds


class Output(object):

    def __init__(self, config):
        self.channel = config['channel']
        self._feed = hpfeeds.new(
            config['host'],
            int(config['port']),
            config['ident'],
            config['secret']
        )
        self._feed.s.settimeout(0.01)

    def send(self, event):
        self._feed.publish([self.channel], json.dumps(event))
