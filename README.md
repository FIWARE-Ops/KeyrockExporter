![FIWARE Banner](https://nexus.lab.fiware.org/content/images/fiware-logo1.png)

# Orion Context Broker exporter for Prometheus
[![Docker badge](https://img.shields.io/docker/pulls/fiware/service.orionexporter.svg)](https://hub.docker.com/r/fiware/service.orionexporter/)
[![Build Status](https://travis-ci.org/FIWARE-Ops/OrionExporter.svg?branch=master)](https://travis-ci.org/FIWARE-Ops/OrionExporter)

## Overview
This project is part of [FIWARE](https://fiware.org) OPS infrastructure.
It provides the possibility to organize [Prometheus](https://prometheus.io/) monitoring of [Orion's](https://fiware-orion.readthedocs.io/en/master/) state. 
Orion can be protected by [Keyrock](https://fiware-idm.readthedocs.io/en/latest/), in this case 
[KeyrockTokenProvider](https://github.com/FIWARE-Ops/KeyrockTokenProvider)  should be define.
It works as a service and allows to check several entities as well.

## How to run
```console
$ docker run -d fiware/service.orionexporter \
             --ip ${IP} \
             --port ${PORT} \
             --config ${PATH_TO_CONFIG}
```
```console
$ curl http://localhost:8000/ping
```

## How to configure
Sample config is located [here](./config-example.json).
If entities are defined, you should provide at least an `id` (the exporter will use this `id` to export metrics) or 
`type`.


## Example of query
```console
curl orionexporter:8000/probe?target=https://wilma.example.com
```

## List of endpoints
+ /probe - endpoint to communicate with Prometheus
+ /ping - returns `pong`
+ /version - returns `build` and `commit`


#### Prometheus config (for this [example](./config-example.json))
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
    expr: orion_check_instance == 0
    for: 3m
    labels:
      severity: "critical"
    annotations:
      summary: "Endpoint {{ $labels.instance }} is down"

  - alert: EntityDown
    expr: orion_check_entities == 0
    for: 3m
    labels:
      severity: "warning"
    annotations:
      summary: "Some problems with entities"
```
