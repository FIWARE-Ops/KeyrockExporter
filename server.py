#!/usr/bin/python3
# -*- coding: utf-8 -*-

import time
import json as jsn
import socket
import threading
import http.server
import requests
import os
import sys
import datetime
import argparse
from urllib.parse import unquote


def parse_request_line(request_line):
    request_line = unquote(unquote(request_line.split('HTTP')[0].strip()))
    cmd = request_line.split('/')[1].strip().split('?')[0]
    param = dict()

    if cmd in ['probe']:
        if len(request_line.split('?')) > 1:
            for el in request_line.split('?')[1].split('&'):
                if el.split('=')[0] in ['target', 'module']:
                    param[el.split('=')[0]] = el.split('=')[1]

    if cmd in cmd_list:
        return cmd, param

    return False, None


def request_token(target, sel):
    auth = requests.auth.HTTPBasicAuth(data[target]['client_id'], data[target]['client_secret'])
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    url = data[target]['keyrock'] + '/oauth2/token'

    if sel == 'request':
        payload = {'grant_type': 'password',
                   'username': data[target]['username'],
                   'password': data[target]['password']}
    elif sel == 'refresh':
        payload = {'grant_type': 'refresh_token',
                   'refresh_token': data[target]['refresh_token']}

    try:
        resp = requests.post(url, auth=auth, data=payload, headers=headers, timeout=5)
    except requests.exceptions.ConnectionError:
        return False, "orion_failed_" + sel + "_token_connection_timeout"

    if resp.status_code == 200:
        reply = jsn.loads(resp.text)
        data[target]['access_token'] = reply['access_token']
        data[target]['refresh_token'] = reply['refresh_token']
        return True, None
    return False, "orion_failed_" + sel + "_token_response_code"


def validate_token(target):
    url = data[target]['keyrock'] + '/user?access_token=' + data[target]['access_token']
    try:
        resp = requests.get(url, timeout=5)
    except requests.exceptions.ConnectionError:
        return False, "orion_failed_validate_token_timeout"

    if resp.status_code in [200, 201]:
        return True, None
    else:
        return False, "orion_failed_validate_token_response_code"


def assign_hash(value, target):
    for el in data:
        if data[el]['target'] == target:
            data[value] = dict()
            data[value] = data.pop(el)
            return True

    return False


def check(target):
    headers = dict()
    entities = dict()

    trg = data[target]['target']

    if 'access_token' in data[target]:
        headers['x-auth-token'] = data[target]['access_token']

    url = trg + '/version'

    try:
        resp = requests.get(url, headers=headers, timeout=5)
    except requests.exceptions.ConnectionError:
        return False, "orion_failed_check_version_timeout"

    if not resp.status_code == 200:
        return False, "orion_failed_check_version_response_code"

    if 'entities' in data[target]:
        for el in data[target]['entities']:
            url = trg + '/v2/entities?limit=1'
            if 'fiware-service' in headers:
                del headers['fiware-service']
            if 'fiware-servicepath' in headers:
                del headers['fiware-servicepath']

            if 'id' in data[target]['entities'][el]:
                url = trg + '/v2/entities/' + data[target]['entities'][el]['id']
            elif 'type' in data[target]['entities'][el]:
                url = trg + '/v2/entities?limit=1&type=' + data[target]['entities'][el]['type']

            if 'service' in data[target]['entities'][el]:
                headers['fiware-service'] = data[target]['entities'][el]['service']

            if 'path' in data[target]['entities'][el]:
                headers['fiware-servicepath'] = data[target]['entities'][el]['path']

            try:
                resp = requests.get(url, headers=headers, timeout=5)
            except requests.exceptions.ConnectionError:
                return False, "orion_failed_check_entity_timeout"

            if resp.status_code == 200:
                tmp = len(jsn.loads(resp.text))
                if 'id' in data[target]['entities'][el] and tmp > 0:
                    entities[el] = 1
                else:
                    entities[el] = tmp
            else:
                return False, "orion_failed_check_entity_response_code"

    return True, entities


class Handler(http.server.BaseHTTPRequestHandler):

    def reply(self, reply=dict(), silent=False, code=200, cmd=''):
        self.send_response(code)
        self.send_header('content-type', 'text/plain')
        self.end_headers()
        if cmd in ['ping', 'version']:
            message = jsn.dumps(reply)
        else:
            message = ''
            for el in sorted(reply):
                message = message + el + ' ' + str(reply[el]) + '\n'

        self.wfile.write(bytes(message, 'utf8'))
        log = dict()
        if not silent:
            log['code'] = code
            if self.headers.get('X-Real-IP'):
                log['ip'] = self.headers.get('X-Real-IP')
            else:
                log['ip'] = self.client_address[0]
            log['request'] = unquote(unquote(self.requestline))
            log['date'] = datetime.datetime.now().isoformat()
            if cmd:
                log['cmd'] = cmd
            if reply:
                log['reply'] = reply
            print(jsn.dumps(log, indent=2))
        return

    def log_message(self, format, *args):
        return

    def do_GET(self):
        message = schema.copy()

        cmd, param = parse_request_line(self.requestline)

        if cmd == 'ping':
            message = {'message': 'Pong'}
            self.reply(message, cmd=cmd)
            return

        if cmd == 'version':
            message = {'message': version}
            self.reply(message, cmd=cmd)
            return

        if cmd == 'probe' and 'target' in param:
            target = hash(param['target']) % ((sys.maxsize + 1) * 2)
            if target not in data:
                if not assign_hash(target, param['target']):
                    message['orion_failed_wrong_target'] = 1
                    self.reply(message, cmd=cmd)
                    return
            if 'keyrock' in data[target]:
                start_time = time.time()

                if 'access_token' not in data[target]:
                    status, reason = request_token(target, 'request')
                    if not status:
                        message[reason] = 1
                        self.reply(message, cmd=cmd)
                        return
                    else:
                        message['orion_token_request'] = 1

                status, reason = validate_token(target)
                if not status:
                    status, reason = request_token(target, 'refresh')
                    if not status:
                        message[reason] = 1
                        self.reply(message, cmd=cmd)
                        return
                    else:
                        message['orion_token_refresh'] = 1
                    status, reason = validate_token(target)
                    if not status:
                        message[reason] = 1
                        self.reply(message, cmd=cmd)
                        return
                end_time = time.time()
                message['orion_time_token'] = end_time - start_time

            start_time = time.time()
            status, entities = check(target)
            if status:
                message['orion_check_success'] = 1
                message['orion_check_entities'] = 1
                if len(entities) > 0:
                    for el in entities:
                        message['orion_check_entity_' + el] = entities[el]
                        if entities[el] == 0:
                            message['orion_check_entities'] = 0

            else:
                message[entities] = 1
                self.reply(message, cmd=cmd)
                return
            end_time = time.time()
            message['orion_time_check'] = end_time - start_time

        else:
            message['orion_failed_wrong_target'] = 1

        self.reply(message, cmd=cmd)
        return


class Thread(threading.Thread):
    def __init__(self, i):
        threading.Thread.__init__(self)
        self.i = i
        self.daemon = True
        self.start()

    def run(self):
        httpd = http.server.HTTPServer(address, Handler, False)

        httpd.socket = sock
        httpd.server_bind = self.server_close = lambda self: None

        httpd.serve_forever()


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--ip', dest="ip", default='0.0.0.0', help='ip address (default: 0.0.0.0)', action="store")
    parser.add_argument('--port', dest="port", default=8000, help='port (default: 8000)', action="store")
    parser.add_argument('--threads', dest='threads', default=3, help='threads to start (default: 3)',
                        action="store")
    parser.add_argument('--socks', dest='socks', default=3, help='threads to start (default: 3)',  action="store")
    parser.add_argument('--config', dest='config_path', default='/opt/config.json',
                        help='path to config file (default: /opt/config.json)',  action="store")

    args = parser.parse_args()

    threads = args.threads
    socks = args.socks
    ip = args.ip
    port = args.port
    config_path = args.config_path
    version_path = os.path.split(os.path.abspath(__file__))[0] + '/version'

    address = (ip, port)

    if not os.path.isfile(config_path):
        print(jsn.dumps({'message': 'Config file not found', 'code': 500, 'cmd': 'start'}, indent=2))
        config_file = None
        sys.exit(1)
    try:
        with open(config_path) as f:
            config = jsn.load(f)
    except ValueError:
        print(jsn.dumps({'message': 'Unsupported config type', 'code': 500, 'cmd': 'start'}, indent=2))
        sys.exit(1)

    version = dict()
    if not os.path.isfile(version_path):
        print(jsn.dumps({'message': 'Version file not found', 'code': 500, 'cmd': 'start'}, indent=2))
        version_file = None
        sys.exit(1)
    try:
        with open(version_path) as f:
            version_file = f.read().split('\n')
            version['build'] = version_file[0]
            version['commit'] = version_file[1]
    except IndexError:
        print(jsn.dumps({'message': 'Unsupported version file type', 'code': 500, 'cmd': 'start'}, indent=2))
        sys.exit(1)

    data = dict()
    try:
        for endpoint in config['endpoints']:
            i = len(data)
            data[i] = dict()

            data[i]["target"] = endpoint["target"]

            if 'entities' in endpoint:
                data[i]['entities'] = dict()
                for entity in endpoint['entities']:
                    data[i]['entities'][entity['metric']] = dict()
                    if 'id' in entity:
                        data[i]['entities'][entity['metric']]["id"] = entity["id"]
                    if 'type' in entity:
                        data[i]['entities'][entity['metric']]["type"] = entity["type"]
                    if 'service' in entity:
                        data[i]['entities'][entity['metric']]["service"] = entity["service"]
                    if 'path' in entity:
                        data[i]['entities'][entity['metric']]["path"] = entity["path"]

            if 'auth' in endpoint:
                data[i]["keyrock"] = endpoint['auth']["keyrock"]
                data[i]["client_id"] = endpoint['auth']["client_id"]
                data[i]["client_secret"] = endpoint['auth']["client_secret"]
                data[i]["username"] = endpoint['auth']["username"]
                data[i]["password"] = endpoint['auth']["password"]
    except KeyError:
        print(jsn.dumps({'message': 'Config is not correct', 'code': 500, 'cmd': 'start'}, indent=2))
        sys.exit(1)

    if len(data) == 0:
        print(jsn.dumps({'message': 'Endpoints list is empty', 'code': 500, 'cmd': 'start'}, indent=2))
        sys.exit(1)

    schema = dict()
    schema['orion_failed_wrong_target'] = 0
    schema['orion_failed_request_token_response_code'] = 0
    schema['orion_failed_request_token_timeout'] = 0
    schema['orion_failed_refresh_token_response_code'] = 0
    schema['orion_failed_refresh_token_timeout'] = 0
    schema['orion_failed_validate_token_response_code'] = 0
    schema['orion_failed_validate_token_timeout'] = 0
    schema['orion_failed_check_version_response_code'] = 0
    schema['orion_failed_check_version_timeout'] = 0
    schema['orion_failed_check_entity_response_code'] = 0
    schema['orion_failed_check_entity_timeout'] = 0
    schema['orion_token_request'] = 0
    schema['orion_token_refresh'] = 0
    schema['orion_check_entities'] = 0
    schema['orion_check_success'] = 0
    schema['orion_time_token'] = 0
    schema['orion_time_check'] = 0

    cmd_list = ['probe', 'ping', 'version']

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(address)
    sock.listen(socks)

    [Thread(i) for i in range(threads)]

    print(jsn.dumps({'message': 'Service started', 'code': 200, 'threads': threads, 'socks': socks}, indent=2))

    while True:
        time.sleep(9999)
