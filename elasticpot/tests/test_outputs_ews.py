import unittest
import unittest.mock

from bottle import Bottle, default_app, request

from elasticpot.outputs import ews

EXPECTED = '''
<EWS-SimpleMessage version="2.0">
    <Authentication>
        <username>dave</username>
        <token>abcdefghijklmnop</token>
    </Authentication>

    <Alert>
        <Analyzer id="foo"/>
        <CreateTime tz="+0100">1 January 1900</CreateTime>
        <Source category="ipv4" port="11111" protocol="tcp">127.0.0.1</Source>
        <Target category="ipv4" port="22222" protocol="tcp">127.0.10.1</Target>
        <Request type="url">http%3A//localhost</Request>
        <Request type="raw">--BASE64 ENCODED STRING HERE--</Request>
        <Request type="description">ElasticSearch Honeypot : Elasticpot</Request>
	<AdditionalData meaning="postdata" type="string">--PAYLOAD%20DATA%20HERE--</AdditionalData>
    </Alert>
</EWS-SimpleMessage>
'''

class TestViews(unittest.TestCase):

    def test_send_event(self):
        output = ews.Output({
            'username': 'dave',
            'token': 'abcdefghijklmnop',
            'rhost_first': 'http://localhost'
        })
        with unittest.mock.patch('requests.post') as post:
            app = Bottle()
            app.config = {'elasticpot': {'nodeid': 'foo'}}
            default_app.push(app)
            request.bind({'bottle.app': app})

            try:
                output.send({
                    'timestamp': '1 January 1900',
                    'src_ip': '127.0.0.1',
                    'src_port': '11111',
                    'dest_ip': '127.0.10.1',
                    'dest_port': '22222',
                    'querystring': '/?pretty',
                    'body': '--PAYLOAD DATA HERE--',
                    'raw': '--BASE64 ENCODED STRING HERE--',
                })
            finally:
                default_app.pop()

            assert post.call_count == 1
            assert post.call_args[0][0] == 'http://localhost'
            assert post.call_args[1]['data'].strip() == EXPECTED.strip()
