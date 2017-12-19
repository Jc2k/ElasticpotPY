from bottle import route, request, response, error, hook
import os
import base64
import datetime
import logging

logger = logging.getLogger("elasticpot.views")

template_folder = os.path.join(os.path.dirname(__file__), 'templates')


@hook('before_request')
def logData():
    querystring = request.path
    if request.query_string:
        querystring += '?' + request.query_string

    headers = '\n'.join(
        ': '.join((h, request.headers[h])) for h in request.headers
    )

    body = ''
    if request.method in ('POST', 'PUT'):
        body = ''.join(chunk.decode('utf-8') for chunk in request.body)

    full_request = ''.join((
        request.method,
        ' ',
        querystring,
        ' ',
        request.environ.get('SERVER_PROTOCOL', 'HTTP/1.0'),
        '\n',
        headers,
        '\n\n',
        body
    ))

    # base64 encode
    raw = base64.b64encode(full_request.encode('utf-8')).decode('ascii')

    curDate = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    data = {}
    data['timestamp'] = curDate
    data['src_ip'] = request.environ.get('REMOTE_ADDR')
    data['src_port'] = request.environ.get('REMOTE_PORT', 44927)
    data['dest_ip'] = request.app.config['main']['ip']
    data['dest_port'] = request.environ['SERVER_PORT']

    data['method'] = request.method
    data['querystring'] = querystring
    data['headers'] = headers
    data['body'] = body
    data['request'] = full_request
    data['raw'] = raw

    request.app.outputs.send(data)


# Handle index site
@route('/', method='GET')
def index():
    logger.info("Scanned (/)")

    response.content_type = 'application/json'

    with open(os.path.join(template_folder, 'index.txt')) as fp:
        return fp.read()


# handle irrelevant / error requests
@error(404)
def error404(error):
    logger.info("Access to non existing resource: " + request.url)

    response.content_type = 'application/json'

    with open(os.path.join(template_folder, '404.txt')) as fp:
        return fp.read()


# handle favicon
@route('/favicon.ico', method='GET')
def favicon():
    with open(os.path.join(template_folder, 'favicon.ico.txt')) as fp:
        return fp.read()


# handle route to indices
@route('/_cat/indices', method='GET')
def getindeces():
    logger.info("Found possible attack (/_cat/indices): " + request.url)

    with open(os.path.join(template_folder, 'getindeces.txt')) as fp:
        return fp.read()


# handle search route (GET)
@route('/_search', method='GET')
def handleSearchExploitGet():
    logger.info("Found possible attack (_search): " + request.url)
    return ""


# handle search route (POST)
@route('/_search', method='POST')
def handleSearchExploit():
    logger.info("Found possible attack (_search): " + request.url)
    return ""


# handle head plugin
@route('/_plugin/head')
def pluginhead():
    logger.info("Access to ElasticSearch head plugin: " + request.url)

    response.content_type = 'text/html'

    with open(os.path.join(template_folder, 'pluginhead.txt')) as fp:
        return fp.read()
