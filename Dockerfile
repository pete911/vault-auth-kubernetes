FROM golang:1.19.3-alpine AS build
RUN apk add --no-cache gcc libc-dev
WORKDIR /go/src/app

COPY . .
RUN go test  ./...
RUN go build -mod vendor -o /bin/vault-auth-kubernetes


FROM alpine:3.16.3
MAINTAINER Peter Reisinger <p.reisinger@gmail.com>
RUN apk add --no-cache ca-certificates

COPY --from=build /bin/vault-auth-kubernetes /usr/local/bin/vault-auth-kubernetes
CMD ["vault-auth-kubernetes"]
