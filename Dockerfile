# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS build
WORKDIR /app
COPY . .
RUN go build -o /aegisr ./cmd/aegisr

FROM alpine:3.20
RUN adduser -D -g '' aegisr
USER aegisr
WORKDIR /home/aegisr
COPY --from=build /aegisr /usr/local/bin/aegisr
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/aegisr"]
CMD ["ingest-http", "-addr", ":8080"]
