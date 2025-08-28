.PHONY: build
build: 
	go generate ./...
	sam build --parameter-overrides architecture=x86_64

.PHONY: local
local: build
	sam local start-api --parameter-overrides architecture=x86_64 -p 3001
