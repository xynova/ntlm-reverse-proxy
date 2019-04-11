FROM golang:1.12 AS builder

# Download and install the latest release of dep
RUN curl -Ls -o /usr/bin/dep https://github.com/golang/dep/releases/download/v0.5.1/dep-linux-amd64 \
    && chmod +x /usr/bin/dep

# Copy the code from the host and compile it
WORKDIR $GOPATH/src/github.com/xynova/ntlm-reverse-proxy
COPY Gopkg.toml Gopkg.lock ./
RUN dep ensure --vendor-only
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix nocgo -o /app .

FROM alpine:3.7
RUN apk add --update ca-certificates
COPY --from=builder /app ./
ENTRYPOINT ["./app"]
