# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 go build -o /out/control-panel ./cmd/control-panel

# distroless:nonroot for CA certs (needed for OIDC over HTTPS) without a
# shell or package manager in the shipped image.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/control-panel ./control-panel
COPY frontend/ ./frontend/

EXPOSE 8090
ENTRYPOINT ["/app/control-panel"]
