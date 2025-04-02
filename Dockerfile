FROM golang:1.21-alpine

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod .
COPY cert/cert.go ./cert/
COPY proxy/proxy_http.go ./proxy/
COPY ca_cert.pem .
COPY ca_key.pem .

RUN go mod download
RUN go build -o proxy-server ./proxy/proxy_http.go

EXPOSE 8080

CMD ["./proxy-server"]