from bottle import route, request, response, error, hook
import requests
import os
import base64
import datetime
import urllib.request
import logging

logger = logging.getLogger("elasticpot.views")

template_folder = os.path.join(os.path.dirname(__file__), 'templates')


@hook('before_request')
def logData():
    if request.query_string == "":
         querystring = ""
    else:
        querystring = "?" + request.query_string

    querystring = request.method + " " + request.path + querystring

    postdata = ""
    if request.method == "POST":
        for l in request.body:
            postdata += l.decode("utf-8")

    # Generate raw http-request manually
    requestheaders = querystring + " " + request.environ.get('SERVER_PROTOCOL') + "\n"

    for header in request.headers:
        requestheaders += header + ': ' + request.headers[header] + '\n'

    if request.method == "POST":
        requestheaders+=postContent+"\n"

    # base64 encode
    raw = base64.b64encode(requestheaders.encode('UTF-8')).decode('ascii')

    curDate = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%dT%H:%M:%S')
    data = {}
    data['timestamp'] = curDate
    data['event_type'] = "alert"
    data['src_ip'] = request.environ.get('REMOTE_ADDR')
    data['src_port'] = request.environ.get('REMOTE_PORT', 44927)
    data['dest_ip'] = request.app.config['main']['ip']
    data['dest_port'] = request.environ['SERVER_PORT']
    data2 = {}
    data2['name'] = "Elasticpot"
    data2['nodeid'] = request.app.config['elasticpot']['nodeid']
    data2['query'] = querystring
    data2['postdata'] = postdata
    data2['raw'] = raw
    data['honeypot'] = data2

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
        fp.read())


# handle route to indices
@route('/_cat/indices', method='GET')
def getindeces():
    logger.info ("Found possible attack (/_cat/indices): " + request.url)

    with open(os.path.join(template_folder, 'getindeces.txt')) as fp:
        return fp.read()


# handle search route (GET)
@route('/_search', method='GET')
def handleSearchExploitGet():
    logger.info ("Found possible attack (_search): " + request.url)
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

    with open(os.path.join(template_folder, 'pluginhead.txt')) as fp:
        return fp.read()
