.PHONY: build
build: 
	go generate ./...
	sam build --parameter-overrides architecture=x86_64

.PHONY: local
local: build
	sam local start-api --host 0.0.0.0 --docker-network icaa-shared --warm-containers EAGER --parameter-overrides architecture=x86_64 --env-vars env.json -p 3001

