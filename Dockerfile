FROM alpine:3
COPY bin/health-checker /bin/health-checker
ENTRYPOINT [ "health-checker" ]
