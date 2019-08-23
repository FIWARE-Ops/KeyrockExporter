![FIWARE Banner](https://nexus.lab.fiware.org/content/images/fiware-logo1.png)

# Orion Context Broker exporter for Prometheus
[![Docker badge](https://img.shields.io/docker/pulls/fiware/service.orionexporter.svg)](https://hub.docker.com/r/fiware/service.orionexporter/)
[![Build Status](https://travis-ci.org/FIWARE-Ops/OrionExporter.svg?branch=master)](https://travis-ci.org/FIWARE-Ops/OrionExporter)

## Overview
This project is part of [FIWARE](https://fiware.org) OPS infrastructure.
It provides the possibility to organize [Prometheus](https://prometheus.io/) monitoring of [Orion's](https://fiware-orion.readthedocs.io/en/master/) state. 
Orion can be protected by [Keyrock](https://fiware-idm.readthedocs.io/en/latest/). 
It works as a service and allows to check several entities as well.

## WARNING
This is an alpha revision.

## How to run
```console
$ docker run -d fiware/service.orionexporter \
             --ip ${IP} \
             --port ${PORT} \
             --threads ${THREADS} \
             --socks ${SOCKS} \
             --config ${PATH_TO_CONFIG} \
```
```console
$ curl http://localhost:8000/ping
```

## How to configure
Sample config is located [here](./config-example.json).
If entities are defined, you should provide at least an 'ID' (the exporter will use this 'ID' to export metrics). 
Make sure that the 'ID' doesn't contain dashes.


## Explanation of logic
Orion's state is checked by sending a request to 'orion:1026/version'. 
It requests and refreshes the access token from Keyrock (if 'auth' is defined in the config).
It returns 0 as 'check_success' if Orion or Keyrock returns other status codes than 200 or 201.
If entities are defined, it sends a request with the parameter '?limit=1' to each entity. If the request returns an empty list, the metric 'check_entities' will be 0,
but the metric 'check_success' will be 1. 
You can determine a specific entity by its 'id' or 'type', an 'id' has a higher priority than 'type'. 
You can also define 'FIWARE-SERVICE' and 'FIWARE-SERVICEPATH'.


## Example of query
+ curl orionexporter:8000/probe?target=https://wilma.example.com


## List of endpoints
+ /probe - endpoint to communicate with Prometheus
+ /ping - returns 'pong'
+ /version - returns 'version' and 'commit


#### Prometheus config (for this [config](./config-example.json))
```console
  - job_name: 'orions'
    scrape_interval: 10m
    metrics_path: /probe
    static_configs:
      - targets:
        - https://wilma.example.com
        - http://orion.example.com:1026
        - http://wilma2.example.com:4444
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: orionexporter:8000
```


#### Prometheus alert rule
```console
groups:
- name: orion.rules
  rules:
  - alert: EndpointDown
    expr: check_success == 0
    for: 3m
    labels:
      severity: "critical"
    annotations:
      summary: "Endpoint {{ $labels.instance }} is down"

  - alert: EntityDown
    expr: check_entity == 0
    for: 3m
    labels:
      severity: "warning"
    annotations:
      summary: "Entity not exists"
```
