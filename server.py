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


def assign_hash(value, target):
    for el in config:
        if config[el]['target'] == target:
            config[value] = dict()
            config[value] = config.pop(el)
            return True

    return False


def check(target):
    headers = dict()
    entities = dict()

    trg = config[target]['target']

    if 'access_token' in config[target]:
        headers['x-auth-token'] = config[target]['access_token']

    url = trg + '/version'

    try:
        resp = requests.get(url, headers=headers, timeout=config[target]['timeout'])
    except requests.exceptions.RequestException:
        return False, "orion_failed_check_version_timeout"

    if not resp.status_code == 200:
        return False, "orion_failed_check_version_response_code"

    if 'entities' in config[target]:
        for el in config[target]['entities']:
            url = trg + '/v2/entities?limit=1'
            if 'fiware-service' in headers:
                del headers['fiware-service']
            if 'fiware-servicepath' in headers:
                del headers['fiware-servicepath']

            if 'id' in config[target]['entities'][el]:
                url = trg + '/v2/entities/' + config[target]['entities'][el]['id']
            elif 'type' in config[target]['entities'][el]:
                url = trg + '/v2/entities?limit=1&type=' + config[target]['entities'][el]['type']

            if 'service' in config[target]['entities'][el]:
                headers['fiware-service'] = config[target]['entities'][el]['service']

            if 'path' in config[target]['entities'][el]:
                headers['fiware-servicepath'] = config[target]['entities'][el]['path']

            try:
                resp = requests.get(url, headers=headers, timeout=config[target]['timeout'])
            except requests.exceptions.RequestException:
                return False, "orion_failed_check_entity_timeout"

            if resp.status_code == 200:
                tmp = len(jsn.loads(resp.text))
                if 'id' in config[target]['entities'][el] and tmp > 0:
                    entities[el] = 1
                else:
                    entities[el] = tmp
            else:
                return False, "orion_failed_check_entity_response_code"

    return True, entities


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
    auth = requests.auth.HTTPBasicAuth(config[target]['client_id'], config[target]['client_secret'])
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    url = config[target]['keyrock'] + '/oauth2/token'

    if sel == 'request':
        payload = {'grant_type': 'password',
                   'username': config[target]['username'],
                   'password': config[target]['password']}
    elif sel == 'refresh':
        payload = {'grant_type': 'refresh_token',
                   'refresh_token': config[target]['refresh_token']}

    try:
        resp = requests.post(url, auth=auth, data=payload, headers=headers, timeout=timeout_keyrock)
    except requests.exceptions.RequestException:
        return False, "orion_failed_" + sel + "_token_connection_timeout"

    if resp.status_code == 200:
        reply = jsn.loads(resp.text)
        config[target]['access_token'] = reply['access_token']
        config[target]['refresh_token'] = reply['refresh_token']
        return True, None
    return False, "orion_failed_" + sel + "_token_response_code"


def validate_token(target):
    url = config[target]['keyrock'] + '/user?access_token=' + config[target]['access_token']
    try:
        resp = requests.get(url, timeout=timeout_keyrock)
    except requests.exceptions.RequestException:
        return False, "orion_failed_validate_token_timeout"

    if resp.status_code in [200, 201]:
        return True, None
    else:
        return False, "orion_failed_validate_token_response_code"


class Handler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        message = schema.copy()

        cmd, param = parse_request_line(self.requestline)

        if not cmd:
            message = {'message': 'Request not found'}
            self.reply(message, code=400)
            return

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
            if target not in config:
                if not assign_hash(target, param['target']):
                    message['orion_failed_wrong_target'] = 1
                    self.reply(message, cmd=cmd)
                    return
            if 'keyrock' in config[target]:
                start_time = time.time()

                if 'access_token' not in config[target]:
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

            self.reply(message, cmd=cmd)
            return

        message = {'message': 'Hook not found', 'param': param}
        self.reply(message, cmd=cmd, code=404)
        return

    def log_message(self, format, *args):
        return

    def reply(self, reply=None, silent=False, code=200, cmd=None):
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
                log['message'] = reply
            print(jsn.dumps(log, indent=2))
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
    parser.add_argument('--timeout_keyrock', dest='timeout_keyrock', default=30,
                        help='request timeout (default: 30)',  action="store")
    parser.add_argument('--timeout_orion', dest='timeout_orion', default=60,
                        help='request timeout (default: 60)',  action="store")
    args = parser.parse_args()

    timeout_keyrock = args.timeout_keyrock
    timeout_orion = args.timeout_orion
    config_path = args.config_path

    address = (args.ip, args.port)
    version_path = os.path.split(os.path.abspath(__file__))[0] + '/version'

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

    if not os.path.isfile(config_path):
        print(jsn.dumps({'message': 'Config file not found', 'code': 500, 'cmd': 'start'}, indent=2))
        config_file = None
        sys.exit(1)
    try:
        with open(config_path) as f:
            cfg = jsn.load(f)
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

    config = dict()
    try:
        for endpoint in cfg['endpoints']:
            i = len(config)
            config[i] = dict()

            config[i]["target"] = endpoint["target"]

            if "timeout" not in endpoint:
                config[i]["timeout"] = timeout_orion
            else:
                config[i]["timeout"] = endpoint["timeout"]

            if 'entities' in endpoint:
                config[i]['entities'] = dict()
                for entity in endpoint['entities']:
                    config[i]['entities'][entity['metric']] = dict()
                    if 'id' in entity:
                        config[i]['entities'][entity['metric']]["id"] = entity["id"]
                    if 'type' in entity:
                        config[i]['entities'][entity['metric']]["type"] = entity["type"]
                    if 'service' in entity:
                        config[i]['entities'][entity['metric']]["service"] = entity["service"]
                    if 'path' in entity:
                        config[i]['entities'][entity['metric']]["path"] = entity["path"]

            if 'auth' in endpoint:
                config[i]["keyrock"] = endpoint['auth']["keyrock"]
                config[i]["client_id"] = endpoint['auth']["client_id"]
                config[i]["client_secret"] = endpoint['auth']["client_secret"]
                config[i]["username"] = endpoint['auth']["username"]
                config[i]["password"] = endpoint['auth']["password"]
    except KeyError:
        print(jsn.dumps({'message': 'Config is not correct', 'code': 500, 'cmd': 'start'}, indent=2))
        sys.exit(1)

    if len(config) == 0:
        print(jsn.dumps({'message': 'Endpoints list is empty', 'code': 500, 'cmd': 'start'}, indent=2))
        sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(address)
    sock.listen(args.socks)

    [Thread(i) for i in range(args.threads)]

    print(jsn.dumps({'message': 'Service started', 'code': 200}, indent=2))

    while True:
        time.sleep(9999)
