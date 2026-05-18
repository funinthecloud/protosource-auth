PROTOSOURCE_VERSION := $(shell awk '/github.com\/funinthecloud\/protosource / {print $$2; exit}' go.mod)
TOFU_DIR := tofu/aws

ADMIN_BUCKET = $(shell tofu -chdir=$(TOFU_DIR) output -raw admin_bucket_name 2>/dev/null)
ADMIN_DIST   = $(shell tofu -chdir=$(TOFU_DIR) output -raw admin_distribution_id 2>/dev/null)

.PHONY: help
help:
	@echo "Targets:"
	@echo "  gen              Regenerate Go and TS protobuf code"
	@echo "  build            Regen + build backend and frontend"
	@echo "  test             go test + frontend tsc"
	@echo "  deploy           Full release: regen, build, sam deploy, sync SPA, invalidate"
	@echo "  deploy-backend   sam build + sam deploy"
	@echo "  deploy-frontend  vite build + s3 sync + cloudfront invalidation"
	@echo "  clean            Remove build artifacts"

.PHONY: tools
tools:
	go install github.com/funinthecloud/protosource/cmd/protoc-gen-protosource@$(PROTOSOURCE_VERSION)
	go install github.com/funinthecloud/protosource/cmd/protoc-gen-protosource-ts@$(PROTOSOURCE_VERSION)
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

.PHONY: gen gen-go gen-ts
gen: gen-go gen-ts

gen-go: tools
	buf generate

gen-ts: tools
	buf generate --template frontend/buf.gen.yaml

.PHONY: build build-backend build-frontend
build: build-backend build-frontend

build-backend: gen-go
	go build ./...

build-frontend: gen-ts
	cd frontend && npm install
	cd frontend && npx tsc -b
	cd frontend && npx vite build

.PHONY: test test-backend test-frontend
test: test-backend test-frontend

test-backend:
	go test ./...

test-frontend:
	cd frontend && npx tsc -b

.PHONY: deploy deploy-backend deploy-frontend invalidate
deploy: build deploy-backend deploy-frontend

deploy-backend:
	sam build
	sam deploy --no-confirm-changeset --no-fail-on-empty-changeset

deploy-frontend: build-frontend
	@test -n "$(ADMIN_BUCKET)" || (echo "ADMIN_BUCKET not set — run 'tofu apply' in $(TOFU_DIR) first" && exit 1)
	aws s3 sync frontend/dist/ s3://$(ADMIN_BUCKET)/ --delete
	$(MAKE) invalidate

invalidate:
	@test -n "$(ADMIN_DIST)" || (echo "ADMIN_DIST not set — run 'tofu apply' in $(TOFU_DIR) first" && exit 1)
	aws cloudfront create-invalidation --distribution-id $(ADMIN_DIST) --paths '/*'

.PHONY: clean
clean:
	rm -rf .aws-sam frontend/dist frontend/src/gen
