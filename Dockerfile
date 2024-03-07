FROM golang:1.22 AS builder

WORKDIR /go/src/github.com/metal-stack/gardener-extension-audit
COPY . .
RUN make install \
 && strip /go/bin/gardener-extension-audit

FROM alpine:3.19
WORKDIR /
COPY charts /charts
COPY --from=builder /go/bin/gardener-extension-audit /gardener-extension-audit
CMD ["/gardener-extension-audit"]
