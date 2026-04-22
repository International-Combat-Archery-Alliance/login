#!/bin/sh
set -e

# Only start collector and fetch SSM key in production (not SAM local)
if [ "$AWS_SAM_LOCAL" != "true" ]; then
    if [ -z "$NEW_RELIC_LICENSE_KEY" ]; then
        NEW_RELIC_LICENSE_KEY=$(
            aws ssm get-parameter \
                --name "/newrelic-license-key" \
                --with-decryption \
                --query "Parameter.Value" \
                --output text
        )
        export NEW_RELIC_LICENSE_KEY
    fi

    /app/awscollector --config /app/otel-config.yaml &
    COLLECTOR_PID=$!
    trap 'kill -TERM $COLLECTOR_PID 2>/dev/null' TERM INT
fi

exec /app/bootstrap
