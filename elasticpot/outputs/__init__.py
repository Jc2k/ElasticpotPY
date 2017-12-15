from . import console, ews, file, hpfeeds


class Outputter(object):
    
    def __init__(self, config):
        self.outputs = []

        for output in config.sections():
            if output.startswith('output_'):
                name = output[7:]
                if name not in globals():
                    print("Unknown output plugin: {}".format(name))
                    continue
                    
                self.outputs.append(getattr(globals()[name], "Output")(config[output]))
        
    def send(self, event):
        for output in self.outputs:
            if getattr(output, 'enabled', False):
                output.send(event)
