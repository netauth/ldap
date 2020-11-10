FROM golang:1.15 as build
WORKDIR /netauth/ldap
COPY . .
RUN go mod vendor && \
        CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' -o /ldapd .

FROM scratch
ENTRYPOINT ["/ldapd"]
COPY --from=build /ldapd /ldapd
