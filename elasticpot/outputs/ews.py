import datetime
import os

import requests


EWS_TXT_PATH = os.path.join(os.path.dirname(__file__), '..', 'templates', 'ews.txt')
with open(EWS_TXT_PATH, 'r') as fp:
    EWS_TXT = fp.read()


class Output(object):
    
    def __init__(self, config):
        self.config = config
        self.enabled = 'username' in config or 'token' in config
    
    def send(self, event):
        xml = EWS_TXT.replace("_IP_", ip)
        xml = xml.replace("_TARGET_", hostip)
        xml = xml.replace("_SRCPORT_", str(srcport))
        xml = xml.replace("_DSTPORT_", str(hostport))
        xml = xml.replace("_USERNAME_", username)
        xml = xml.replace("_TOKEN_", token)
        xml = xml.replace("_URL_", quote(str(querystring)))
        xml = xml.replace("_RAW_", raw)
        xml = xml.replace("_DATA_", quote(str(postdata)))
        xml = xml.replace("_NODEID_", nodeid)

        curDate = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S')

        xml = xml.replace("_TIME_", curDate)

        headers = {'Content-Type': 'application/xml'}

        # fix ignorecert to verifycert logic

        if (ignorecert == None):
            ignorecert = True
        elif (ignorecert == "true"):
            ignorecert = False
        elif (ignorecert == "false"):
            ignorecert = True

        try:
            requests.post(server, data=xml, headers=headers, verify=ignorecert, timeout=5)
        except requests.exceptions.Timeout:
            print("Elasticpot: Error trying to submit attack: Connection timeout.")
        except requests.exceptions.RequestException as e:
            print(e)
