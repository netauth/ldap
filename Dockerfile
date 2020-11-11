FROM golang:1.15-alpine as build
WORKDIR /netauth/ldap
COPY . .
RUN go mod vendor && \
        CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' -o /ldapd . && \
        apk add upx binutils && \
        strip /ldapd && \
        upx /ldapd && \
        ls -alh /ldapd

FROM scratch
LABEL org.opencontainers.image.source https://github.com/netauth/ldap
ENTRYPOINT ["/ldapd"]
COPY --from=build /ldapd /ldapd
