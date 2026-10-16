# micromdm/scep's SCEP client, a real third-party client for the interoperability test (server/test/scep-interop.test.ts).
# micromdm publishes no image with the client in it, so it is built from its source at a release.
FROM golang:1.24-alpine AS build
ARG SCEP_VERSION=v2.3.0
RUN CGO_ENABLED=0 go install github.com/micromdm/scep/v2/cmd/scepclient@${SCEP_VERSION}

FROM alpine:3.20
COPY --from=build /go/bin/scepclient /usr/local/bin/scepclient
COPY enroll.sh /usr/local/bin/enroll
ENTRYPOINT ["/usr/local/bin/enroll"]
