from bottle import route, run, request, response, error, default_app
import requests
import os
import configparser
import base64
import datetime
import ipaddress
import urllib.request
import json

from .outputs import Outputter


##########################
# Config section
##########################

configfile = "elasticpot.cfg"   # point to elasticpot.cfg or an ews.cfg if you use ewsposter
template_folder = os.path.join(os.path.dirname(__file__), 'templates')

##########################
# FUNCTIONS
##########################

def readConfig():
    config = configparser.ConfigParser()
    
    config['main'] = {
        'ip': '127.0.0.1',
    }

    config['elasticpot'] = {
        'nodeid': 'elasticpot-community-1',
        'elasticpot': 'True',
    }

    config['output_console'] = {
        'enabled': 'True',
    }

    config['output_ews'] = {
        'enabled': 'False',
        'username': '',
        'token': '',
        'rhost_first': '',
        'ignorecert': 'False',
    }

    config['output_file'] = {
        'enabled': 'False',
        'logfile': 'elasticpot.log',
        
    }

    config['output_hpfeeds'] = {
        'enabled': 'False',
        'host': 'localhost',
        'port': '',
        'ident': '',
        'secret': '',
        'channel': 'elasticpot',
    }

    if os.path.exists(configfile):
        config.read(configfile)
    
    for section in config.sections():
        for key in config[section].keys():
            envkey = '{}_{}'.format(section, key).upper()
            if envkey in os.environ:
                print("Setting {}.{} from environment".format(section, key))
                config[section][key] = os.environ[envkey]

    if not config['main']['ip'] or not ipaddress.ip_address(config['main']['ip']).is_private:
        host_ip = requests.get('https://ifconfig.co/json').json()['ip']
        print("Elasticpot: IP in config file is private. Determined the public IP %s" % host_ip)
        config['main']['ip'] = host_ip

    return config


# re-assemble raw http request from request headers, return base64 encoded
def createRaw(request):
    # Generate querystring
    if request.query_string=="":
         querystring=""
    else:
        querystring= "?"+ request.query_string
    httpreq = request.method + " " +request.path + querystring

    # Get post content
    if request.method == "POST":
        postContent = ""
        for l in request.body:
            postContent += l.decode("utf-8")

	# Generate raw http-request manually
    requestheaders=httpreq + " " + request.environ.get('SERVER_PROTOCOL') + "\n"

    for header in request.headers:
        requestheaders += header + ': ' + request.headers[header] + '\n'
    if request.method == "POST":
        requestheaders+=postContent+"\n"

    # base64 encode
    requestheaders64=base64.b64encode(requestheaders.encode('UTF-8')).decode('ascii')
    return requestheaders64


# Send data to either logfile (for ewsposter, location from ews.cfg) or directly to ews backend
def logData():
    if request.query_string == "":
         querystring = ""
    else:
        querystring = "?" + request.query_string

    querystring = request.method + " " + request.path + querystring

    if request.method == "POST":
        postdata = ""
        for l in request.body:
            postdata += l.decode("utf-8")

	# Create request headers for raw request
    raw = createRaw(request)

    curDate = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%dT%H:%M:%S')
    data = {}
    data['timestamp'] = curDate
    data['event_type'] = "alert"
    data['src_ip'] = request.environ.get('REMOTE_ADDR')
    data['src_port'] = request.environ.get('REMOTE_PORT', 44927)
    data['dest_ip'] = config['main']['ip']
    data['dest_port'] = request.environ['SERVER_PORT']
    data2 = {}
    data2['name'] = "Elasticpot"
    data2['nodeid'] = config['elasticpot']['nodeid']
    data2['name'] = "Elasticpot"
    data2['query'] = querystring
    data2['postdata'] = postdata
    data2['raw'] = raw
    data['honeypot'] = data2
    
    outputter.send(data)


##########################
####### SITE HANDLER
##########################

# Handle index site
@route('/', method='GET')
def index():
    response.content_type = 'application/json'

    txt = open(os.path.join(template_folder, 'index.txt'))
    indexData = txt.read()

    # Not an attack
    # Return data, do nothing
    return indexData


# handle irrelevant / error requests
@error(404)
def error404(error):
    response.content_type = 'application/json'

    txt = open(os.path.join(template_folder, '404.txt'))
    indexData = txt.read()

    # DO WE WANT TO LOG THESE???

	# Log request to console
    print("Elasticpot: Access to non existing ressource: " + request.url)

	# Log the data
    logData()


    # Return data
    return indexData

# handle favicon
@route('/favicon.ico', method='GET')
def getindeces():
    txt = open(os.path.join(template_folder, 'favicon.ico.txt'))
    indexData = txt.read()

    # Not an attack
    # Return default data, do nothing
    return indexData

# handle route to indices
@route('/_cat/indices', method='GET')
def getindeces():
    txt = open(os.path.join(template_folder, 'getindeces.txt'))
    indexData = txt.read()

    # Log request to console
    print ("Elasticpot: Found possible attack (/_cat/indices): " + request.url)

    # Log the data
    logData()

    # Return data
    return indexData

# handle search route (GET)
@route('/_search', method='GET')
def handleSearchExploitGet():

    # Log request to console
    print ("Elasticpot: Found possible attack (_search): " + request.url)

	# Log the data
    logData()

    return ""


# handle search route (POST)
@route('/_search', method='POST')
def handleSearchExploit():

    # Log request to console
    print("Elasticpot: Found possible attack (_search): " + request.url)

	# Log the data
    logData()

    return ""


# handle head plugin
@route('/_plugin/head')
def pluginhead():
    txt = open(os.path.join(template_folder, 'pluginhead.txt'))
    indexData = txt.read()

    # Log request to console
    print("Elasticpot: Access to ElasticSearch head plugin: " + request.url)

	# Log the data
    logData()

    # Return data
    return indexData

### More routes to add...


#@route('/<index:path>?pretty', method='PUT')
#def createindex(index):

##########################
##### MAIN START
##########################

config = readConfig()
outputter = Outputter(config)

application = default_app()
