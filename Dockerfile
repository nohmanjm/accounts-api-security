# One static binary on distroless, non-root — the assumption the Falco rules and admission baseline depend on
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY app/go.mod ./
COPY app/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /accounts-api .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /accounts-api /accounts-api
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/accounts-api"]
