FROM alpine:20221110
COPY health-checker /bin/health-checker
ENTRYPOINT [ "health-checker" ]
