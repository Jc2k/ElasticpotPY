import json


class Output(object):
    
    def __init__(self, config):
        pass
    
    def send(self, event):
        print(json.dumps(event))
