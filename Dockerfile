# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /gateway ./cmd/gateway/ && \
    CGO_ENABLED=0 go build -o /bastion ./cmd/bastion/

FROM scratch
COPY --from=build /gateway /gateway
COPY --from=build /bastion /bastion
COPY policy.example.yaml /policy.yaml
EXPOSE 8080
ENTRYPOINT ["/gateway"]
