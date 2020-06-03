FROM golang:alpine as glide

RUN apk update
WORKDIR /go/src/prometheus-msteams
COPY . /go/src/prometheus-msteams
RUN go build cmd/server/main.go

FROM alpine:3.9.5

RUN apk --no-cache add ca-certificates tini
LABEL description="A lightweight Go Web Server that accepts POST alert message from Prometheus Alertmanager and sends it to Microsoft Teams Channels using an incoming webhook url."

COPY ./default-message-card.tmpl /default-message-card.tmpl
COPY ./ca.pem /usr/local/share/ca-certificates/ca.pem
COPY --from=glide /go/src/prometheus-msteams/main ./promteams
RUN update-ca-certificates

ENTRYPOINT ["/sbin/tini", "--", "/promteams"]

EXPOSE 2000
