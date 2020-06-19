# health-checker

## Description

`health-checker` is used to verify that websites are healthy following a deploy.

## Installation

TBD

## Usage

```sh
TBD
```

## Examples

Run the command like this:

```sh
bin/health-checker --schemes http,https --hosts "www.truss.works" --tries 10 --backoff 3 --log-level info --timeout 15m --paths "/"
```

Output will appear like this:

```text
2020-06-19T10:02:16.014-0700    INFO    health-checker/main.go:297      HTTP GET request completed      {"try": 0, "url": "http://www.truss.works/", "code": 200}
2020-06-19T10:02:16.662-0700    INFO    health-checker/main.go:297      HTTP GET request completed      {"try": 0, "url": "https://www.truss.works/", "code": 200}
```
