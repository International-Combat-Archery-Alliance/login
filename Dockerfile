FROM golang:1.25-alpine AS build_base

WORKDIR /app

ADD go.mod go.sum /app/
RUN go mod download

ADD . /app/

RUN go build -o bootstrap cmd/main.go

FROM public.ecr.aws/aws-observability/aws-otel-collector:v0.47.0 AS collector

FROM alpine

RUN apk add ca-certificates aws-cli

COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:0.9.1 /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=build_base /app/bootstrap /app/bootstrap
COPY --from=collector /awscollector /app/awscollector

COPY otel-config.yaml /app/otel-config.yaml
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENV PORT=8000
EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
