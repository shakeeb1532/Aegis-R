FROM alpine:3.20

RUN apk add --no-cache ca-certificates coreutils curl
RUN adduser -D -g '' aman

USER aman
WORKDIR /home/aman

# The binary is supplied by the build pipeline (no source code in image).
COPY aman /usr/local/bin/aman
COPY deploy/sidecar/entrypoint.sh /usr/local/bin/aman-sidecar

ENTRYPOINT ["/usr/local/bin/aman-sidecar"]
