import logging

from . import console, ews, file, hpfeeds


logger = logging.getLogger('elasticpot.outputs')


class Outputter(object):
    
    def __init__(self, config):
        self.outputs = []

        for output in config.sections():
            if output.startswith('output_'):
                name = output[7:]
                if name not in globals():
                    print("Unknown output plugin: {}".format(name))
                    continue
                    
                enabled = config[output].get('enabled', 'False').lower()
                if enabled in ('1', 'on', 'true', 'yes'):
                    self.outputs.append(getattr(globals()[name], "Output")(config[output]))

        logger.debug('{} outputs are enabled'.format(len(self.outputs)))

    def send(self, event):
        for output in self.outputs:
            logger.debug('Sending event via output {}'.format(output))
            output.send(event)
