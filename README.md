# health-checker

## Description

`health-checker` is used to verify that websites are healthy following a deploy.

## Installation

TBD

## Usage

```sh
Website Health Check

Usage:
  health-checker [command]

Available Commands:
  check       Website Health Check
  completion  Generates bash completion scripts
  help        Help about any command
  version     Print the version

Flags:
  -h, --help   help for health-checker

Use "health-checker [command] --help" for more information about a command.
```

## Examples

Run the command like this:

```sh
bin/health-checker check --schemes http,https --hosts "www.truss.works" --tries 10 --backoff 3 --log-level info --timeout 15m --paths "/"
```

Output will appear like this:

```text
2020-06-19T10:02:16.014-0700    INFO    health-checker/main.go:297      HTTP GET request completed      {"try": 0, "url": "http://www.truss.works/", "code": 200}
2020-06-19T10:02:16.662-0700    INFO    health-checker/main.go:297      HTTP GET request completed      {"try": 0, "url": "https://www.truss.works/", "code": 200}
```

When mutual TLS authentication is required this command can be used like this:

```sh
bin/health-checker check --schemes https --hosts "www.truss.works" --key "${KEY}" --cert "${CERT}" --ca "${CA}" --tries 10 --backoff 3 --log-level info --timeout 15m
```

To ensure there's no issue with reading the KEY, CERT, and CA the values must be base64 encoded. One way to do this is
on the command line:

```sh
export KEY=$(echo $tls_key -q | base64 -i -)
export CERT=$(echo $tls_cert -q | base64 -i -)
export CA=$(echo $ca_cert -q | base64 -i -)
```
