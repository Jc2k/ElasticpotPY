import json
import unittest
import unittest.mock

from bottle import Bottle, default_app, request

from elasticpot.outputs import file


class TestViews(unittest.TestCase):

    def test_send_event(self):
        output = file.Output({'jsonpath': '/dev/null'})
        with unittest.mock.patch.object(output, '_outputfile') as fp:
            app = Bottle()
            app.config = {'elasticpot': {'nodeid': 'foo'}}
            default_app.push(app)
            request.bind({'bottle.app': app})
            try:
                output.send({
                    'timestamp': '',
                    'src_ip': '127.0.0.1',
                    'src_port': '11111',
                    'dest_ip': '127.0.10.1',
                    'dest_port': '22222',
                    'querystring': '/?pretty',
                    'body': '',
                    'raw': '',
                })
            finally:
                default_app.pop()
            assert fp.write.call_count == 1
            assert fp.write.call_args[0][0].endswith('\n')

            event = json.loads(fp.write.call_args[0][0])
            assert isinstance(event, dict)
            assert event['honeypot']['name'] == 'Elasticpot'
