FROM golang:1.23-alpine AS build
RUN go install www.bamsoftware.com/git/dnstt.git/dnstt-server@latest

FROM alpine:3.20
COPY --from=build /go/bin/dnstt-server /usr/local/bin/dnstt-server
ENTRYPOINT ["/usr/local/bin/dnstt-server"]
