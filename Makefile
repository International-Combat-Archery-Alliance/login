.PHONY: build
build: 
	go generate ./...
	sam build --parameter-overrides architecture=x86_64

.PHONY: local
local: build
	sam local start-api --docker-network icaa-shared --parameter-overrides architecture=x86_64 --env-vars env.json -p 3001
