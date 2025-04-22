FROM golang:1.21-alpine

RUN apk add --no-cache git gcc musl-dev

WORKDIR /app

COPY go.mod go.sum .
COPY . .

RUN go mod tidy
RUN go build -o proxy-server ./proxy/proxy_http.go

EXPOSE 8080
EXPOSE 8000

CMD ["./proxy-server"]