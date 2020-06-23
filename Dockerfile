FROM alpine:3
COPY health-checker /bin/health-checker
ENTRYPOINT [ "health-checker" ]
