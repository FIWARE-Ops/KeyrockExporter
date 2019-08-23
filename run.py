#!/usr/bin/python3
# -*- coding: utf-8 -*-

from aiohttp import web, ClientSession, ClientConnectorError
from argparse import ArgumentParser
from asyncio import create_task, gather, TimeoutError, set_event_loop_policy, new_event_loop, set_event_loop
from copy import deepcopy
from logging import error, getLogger
from os import path
from uvloop import EventLoopPolicy
from yajl import dumps, loads

config = dict()
version = dict()
routes = web.RouteTableDef()

auth = None
cipher_suite = None
cookie_name = 'OAuth2Provider'
http_ok = [200, 201, 204]
location = None
request_loop = None

schema = {
    'orion_failed_unknown_error': 0,
    'orion_failed_wrong_target': 0,
    'orion_failed_request_token_connection_error': 0,
    'orion_failed_request_token_connection_timeout': 0,
    'orion_failed_request_token_response_code': 0,
    'orion_failed_check_instance_connection_error': 0,
    'orion_failed_check_instance_connection_timeout': 0,
    'orion_failed_check_instance_response_code': 0,
    'orion_request_token': 0,
    'orion_check_entities': 0,
    'orion_check_instance': 0
}


@routes.get('/ping')
async def get_handler(request):
    return web.Response(text = 'Pong')


@routes.get('/version')
async def get_handler(request):
    return web.Response(text=version)


@routes.get('/probe')
async def get_handler(request):

    reply = deepcopy(schema)
    headers = dict()

    try:
        target = request.rel_url.query['target']
    except KeyError:
        reply['orion_failed_wrong_target'] = 1
        return web.Response(text=prepare_output(reply))

    if target not in config:
        reply['orion_failed_wrong_target'] = 1
        return web.Response(text=prepare_output(reply))

    # Fill in schema with entities
    if 'entities' in config[target]:
        for item in config[target]['entities']:
            reply['orion_check_entity_' + item['metric']] = 0
            reply['orion_failed_entity_' + item['metric'] + '_connection_error'] = 0
            reply['orion_failed_entity_' + item['metric'] + '_connection_timeout'] = 0
            reply['orion_failed_entity_' + item['metric'] + '_response_code'] = 0

    # request token:
    if 'auth' in config[target]:
        async with ClientSession() as session:
            status = -1
            url = config[target]['auth']['tokenprovider']
            timeout = config[target]['auth']['timeout']
            data = config[target]['auth']['data']

            try:
                async with session.post(url, data=data, timeout=timeout) as response:
                    status = response.status
                    text = await response.text()

            except ClientConnectorError:
                reply['orion_failed_request_token_connection_error'] = 1
                return web.Response(text=prepare_output(reply))
            except TimeoutError:
                reply['orion_failed_request_token_connection_timeout'] = 1
                return web.Response(text=prepare_output(reply))
            except Exception as exception:
                reply['orion_failed_unknown_error'] = 1
                logging.error('request_token, %s, %s, %s', status, text, exception)
                return web.Response(text=prepare_output(reply))

            if response.status != 200:
                reply['orion_failed_request_token_response_code'] = 1
                return web.Response(text=prepare_output(reply))
            else:
                reply['orion_request_token'] = 1
                headers['X-AUTH-TOKEN'] = await response.text()

    # check instance
    async with ClientSession() as session:
        status = -1
        url = config[target]['instance']['url']
        timeout = config[target]['instance']['timeout']

        try:
            async with session.get(url, headers=headers, timeout=timeout) as response:
                status = response.status
                text = await response.text()

        except ClientConnectorError:
            reply['orion_failed_check_instance_connection_error'] = 1
            return web.Response(text=prepare_output(reply))
        except TimeoutError:
            reply['orion_failed_check_instance_connection_timeout'] = 1
            return web.Response(text=prepare_output(reply))
        except Exception as exception:
            reply['orion_failed_unknown_error'] = 1
            logging.error('request_token, %s, %s, %s', status, text, exception)
            return web.Response(text=prepare_output(reply))

        if status != 200:
            reply['orion_failed_check_instance_response_code'] = 1
            return web.Response(text=prepare_output(reply))
        else:
            reply['orion_check_instance'] = 1

    # entity check
    if 'entities' in config[target]:
        if 'auth' in config[target]:
            for item in range(0, len(config[target]['entities'])):
                config[target]['entities'][item]['headers'].update(headers)

        async with ClientSession() as session:
            result = await gather(*[create_task(fetch(session, entity)) for entity in config[target]['entities']])

        for item in result:
            reply['orion_check_entities'] = 1

            reply['orion_check_entity_' + item[0]] = 0
            reply['orion_failed_entity_' + item[0] + '_connection_error'] = 0
            reply['orion_failed_entity_' + item[0] + '_connection_timeout'] = 0
            reply['orion_failed_entity_' + item[0] + '_response_code'] = 0

            if item[1] == 200:
                reply['orion_check_entity_' + item[0]] = 1
            elif item[1] == 502:
                reply['orion_failed_entity_' + item[0] + '_connection_error'] = 1
            elif item[1] == 504:
                reply['orion_failed_entity_' + item[0] + '_connection_timeout'] = 1
            else:
                reply['orion_failed_entity_' + item[0] + '_response_code'] = 1

            if item[1] != 200:
                reply['orion_check_entities'] = 0

    reply = dumps(dict(sorted(reply.items(), key = lambda k: (k[0], k[1]))), indent=0)
    return web.Response(text=reply[reply.find('\n') + 1:reply.rfind('\n')])


def prepare_output(reply):
    reply = dumps(dict(sorted(reply.items(), key = lambda k: (k[0], k[1]))), indent=0)
    return reply[reply.find('\n') + 1:reply.rfind('\n')]


async def fetch(session, item):
    status = -1
    try:
        async with session.get(item['url'], headers=item['headers'], timeout=item['timeout']) as response:
            status = response.status
            text = await response.read()
    except ClientConnectorError:
        status = 502
    except TimeoutError:
        status = 504
    except Exception as exception:
        error('unknown error, %s, %s, %s', exception, status, text)

    return item['metric'], status


if __name__ == '__main__':

    parser = ArgumentParser()
    parser.add_argument('--ip', default='0.0.0.0', help='ip to use, default is 0.0.0.0')
    parser.add_argument('--port', default=8080, help="port to use, default is 8080")
    parser.add_argument('--config', default='/opt/config.json', help='path to config file, default is /opt/config.json')

    args = parser.parse_args()

    getLogger().setLevel(40)
    set_event_loop_policy(EventLoopPolicy())

    version_path = './version'
    if not path.isfile(version_path):
        error('Version file not found')
        exit(1)
    try:
        with open(version_path) as f:
            version_file = f.read().split('\n')
            version['build'] = version_file[0]
            version['commit'] = version_file[1]
            version = dumps(version)
    except IndexError:
        error('Unsupported version file type')
        exit(1)

    if not path.isfile(args.config):
        error('Config file not found')
        exit(1)

    try:
        with open(args.config) as file:
            temp = loads(file.read())
    except ValueError:
        error('Unsupported config type')
        exit(1)
    try:
        for endpoint in temp['endpoints']:
            config[endpoint['target']] = dict()
            config[endpoint['target']]['instance'] = dict()
            config[endpoint['target']]['instance']['url'] = endpoint['target'] + '/version'
            if 'timeout' not in endpoint:
                config[endpoint['target']]['instance']['timeout'] = None
            else:
                config[endpoint['target']]['instance']['timeout'] = endpoint['timeout']

            if 'entities' in endpoint:
                config[endpoint['target']]['entities'] = list()
                for entity_src in endpoint['entities']:
                    entity_trg = dict()
                    if 'id' in entity_src:
                        entity_trg['url'] = endpoint['target'] + '/v2/entities?id=' + entity_src['id']
                    elif 'type' in entity_src:
                        entity_trg['url'] = endpoint['target'] + '/v2/entities?type=' + entity_src['type']
                    else:
                        error('Neither id, neither type not defined in entity config')
                        exit(1)

                    entity_trg['metric'] = entity_src['metric']

                    if 'service' in entity_src:
                        if 'headers' not in entity_trg:
                            entity_trg['headers'] = dict()

                        entity_trg['headers']['FIWARE-Service'] = entity_src['service']

                    if 'timeout' in entity_src:
                        entity_trg['timeout'] = entity_src['timeout']
                    else:
                        entity_trg['timeout'] = None

                    config[endpoint['target']]['entities'].append(entity_trg)

            if 'auth' in endpoint:
                config[endpoint['target']]['auth'] = dict()
                config[endpoint['target']]['auth']['tokenprovider'] = endpoint['auth']['tokenprovider']

                if 'timeout' in endpoint['auth']:
                    config[endpoint['target']]['auth']['timeout'] = endpoint['auth']['timeout']
                else:
                    config[endpoint['target']]['auth']['timeout'] = None

                auth_data = 'username=' + endpoint['auth']['username'] + '&password=' + endpoint['auth']['password']
                config[endpoint['target']]['auth']['data'] = auth_data

                if 'entities' in config[endpoint['target']]:
                    for i in range(0, len(config[endpoint['target']]['entities'])):
                        if 'headers' not in config[endpoint['target']]['entities'][i]:
                            config[endpoint['target']]['entities'][i]['headers'] = dict()

    except KeyError:
        error('Config is not correct')
        exit(1)

    if len(config) == 0:
        error('Config is empty')
        exit(1)

    request_loop = new_event_loop()
    app_loop = new_event_loop()

    set_event_loop(app_loop)

    app = web.Application()
    app.add_routes(routes)

    web.run_app(app, host=args.ip, port=args.port)
