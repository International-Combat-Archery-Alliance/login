FROM golang:1.25-alpine AS build_base

WORKDIR /app

ADD go.mod go.sum /app/
RUN go mod download

ADD . /app/

RUN go build -o bootstrap ./cmd

FROM alpine

RUN apk add ca-certificates

COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:0.9.1 /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=build_base /app/bootstrap /app/bootstrap

ENV PORT=8000
EXPOSE 8000

CMD ["/app/bootstrap"]
