# ElasticPot - an Elasticsearch honeypot

Written by Andre Vorbach and Markus Schmall

- compatible with DTAG T-Pot environment
- available also as dockerized versions (see docker hub)


Contact:

markus_@_mschmall_de_
andre_@_vorbach_org


## Installation hints

### Docker

On any Linux, macOS or Windows system with Docker and docker-compose you can:

```
docker-compose build
docker-compose up
```

And get a copy of the honeypot running on 127.0.0.1:9200.


### macOS

Use [brew](https://brew.sh/) to install Python 3:

```
brew install python 3
```

Install dependencies e.g. with pip

```
pip install -r requirements.txt
```

See the `Dockerfile` for the dependencies in general.

or see the ansible playbook :)
