# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS build
WORKDIR /app
COPY . .
RUN go build -o /aman ./cmd/aman

FROM alpine:3.20
RUN adduser -D -g '' aman
USER aman
WORKDIR /home/aman
COPY --from=build /aman /usr/local/bin/aman
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/aman"]
CMD ["ingest-http", "-addr", ":8080"]
