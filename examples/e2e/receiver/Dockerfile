FROM golang:1.27.3-alpine AS builder
WORKDIR /src
COPY go.mod *.go ./
RUN CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go build -trimpath -o /receiver .

FROM scratch
COPY --from=builder /receiver /receiver
USER 65532:65532
EXPOSE 8090
ENTRYPOINT ["/receiver"]
