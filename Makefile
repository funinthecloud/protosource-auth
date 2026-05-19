PROTOSOURCE_VERSION := $(shell awk '/github.com\/funinthecloud\/protosource / {print $$2; exit}' go.mod)
TOFU_DIR := tofu/aws
TOFU_AZURE_DIR := tofu/azure

# Azure container image — set CONTAINER_IMAGE on the make line, e.g.
#   make deploy-azure CONTAINER_IMAGE=myacr.azurecr.io/protosource-auth:v1
# After the first apply the upstream container-app-service module
# emits acr_login_server as a tofu output that you can plumb back in.
CONTAINER_IMAGE ?=

ADMIN_BUCKET = $(shell tofu -chdir=$(TOFU_DIR) output -raw admin_bucket_name 2>/dev/null)
ADMIN_DIST   = $(shell tofu -chdir=$(TOFU_DIR) output -raw admin_distribution_id 2>/dev/null)

.PHONY: help
help:
	@echo "Targets:"
	@echo "  gen              Regenerate Go and TS protobuf code"
	@echo "  build            Regen + build backend and frontend"
	@echo "  test             go test + frontend tsc"
	@echo "  deploy           Full AWS release: regen, build, tofu apply, sync SPA, invalidate"
	@echo "  deploy-backend   AWS tofu apply (builds Lambda binary and ships it)"
	@echo "  deploy-frontend  vite build + s3 sync + cloudfront invalidation"
	@echo ""
	@echo "Azure:"
	@echo "  build-container  Build the Container Apps image from cmd/protosource-auth/Dockerfile"
	@echo "  push-azure       Build + push the image to the ACR created by tofu/azure"
	@echo "  deploy-azure     tofu apply against tofu/azure with the pushed image"
	@echo ""
	@echo "  clean            Remove build artifacts"
	@echo ""
	@echo "Required env for frontend builds:"
	@echo "  VITE_API_BASE    API origin (e.g. https://auth.example.com)"
	@echo "  VITE_AUTH_URL    Login redirect origin (usually same as VITE_API_BASE)"

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
	@test -n "$(VITE_API_BASE)" || (echo "VITE_API_BASE not set — e.g. VITE_API_BASE=https://auth.example.com make build-frontend" && exit 1)
	cd frontend && npm install
	cd frontend && npx tsc -b
	cd frontend && VITE_API_BASE="$(VITE_API_BASE)" VITE_AUTH_URL="$(VITE_AUTH_URL)" npx vite build

.PHONY: test test-backend test-frontend
test: test-backend test-frontend

test-backend:
	go test ./...

test-frontend:
	cd frontend && npx tsc -b

.PHONY: deploy deploy-backend deploy-frontend invalidate
deploy: build deploy-backend deploy-frontend

deploy-backend: gen-go
	tofu -chdir=$(TOFU_DIR) apply -auto-approve

deploy-frontend: build-frontend
	@test -n "$(ADMIN_BUCKET)" || (echo "ADMIN_BUCKET not set — run 'tofu apply' in $(TOFU_DIR) first" && exit 1)
	aws s3 sync frontend/dist/ s3://$(ADMIN_BUCKET)/ --delete
	$(MAKE) invalidate

invalidate:
	@test -n "$(ADMIN_DIST)" || (echo "ADMIN_DIST not set — run 'tofu apply' in $(TOFU_DIR) first" && exit 1)
	aws cloudfront create-invalidation --distribution-id $(ADMIN_DIST) --paths '/*'

.PHONY: build-container push-azure deploy-azure
# DOCKER_PLATFORM picks the target arch for the image. Container Apps
# accepts both linux/amd64 and linux/arm64; the default leaves it
# unset so docker builds for the host (which is what most CI / local
# dev wants). Override on Apple Silicon when pushing to an amd64-only
# ACR repo, or set "linux/amd64,linux/arm64" for a buildx multi-arch
# manifest.
DOCKER_PLATFORM ?=
DOCKER_PLATFORM_FLAG = $(if $(DOCKER_PLATFORM),--platform $(DOCKER_PLATFORM),)

# Builds the Container Apps image. CONTAINER_IMAGE is the full
# <registry>/<repo>:<tag> tag to apply (and, in push-azure, push). Use
# the acr_login_server tofu output for the registry part.
build-container:
	@test -n "$(CONTAINER_IMAGE)" || (echo "CONTAINER_IMAGE not set — e.g. CONTAINER_IMAGE=myacr.azurecr.io/protosource-auth:dev make build-container" && exit 1)
	docker build $(DOCKER_PLATFORM_FLAG) -f cmd/protosource-auth/Dockerfile -t $(CONTAINER_IMAGE) .

# Pushes to ACR. Requires a prior `az acr login --name <acr-name>` so
# Docker has credentials; the make recipe doesn't run az for you since
# it may prompt interactively.
push-azure: build-container
	docker push $(CONTAINER_IMAGE)

# Two-stage workflow:
#   1. First apply with CONTAINER_IMAGE empty stands up the ACR with
#      the upstream quickstart image (defaulted in tofu/azure/variables.tf).
#   2. Push your image (see push-azure) and re-run with CONTAINER_IMAGE
#      pointing at the ACR-hosted tag.
#
# Required env (forwarded via TF_VAR_*):
#   TF_VAR_subscription_id   Azure subscription id to deploy into
#   TF_VAR_issuer_iss        JWT `iss` for the default issuer (e.g. https://auth.example.com)
# Optional: any other tofu/azure/variables.tf input can be overridden
# via TF_VAR_<name> without editing this target.
deploy-azure:
	@test -n "$$TF_VAR_subscription_id" || (echo "TF_VAR_subscription_id not set — export TF_VAR_subscription_id=<azure-sub-id> before running" && exit 1)
	@test -n "$$TF_VAR_issuer_iss" || (echo "TF_VAR_issuer_iss not set — export TF_VAR_issuer_iss=https://auth.example.com before running" && exit 1)
	tofu -chdir=$(TOFU_AZURE_DIR) apply $(if $(CONTAINER_IMAGE),-var image=$(CONTAINER_IMAGE),)

.PHONY: clean
clean:
	rm -rf frontend/dist frontend/src/gen tofu/aws/.build
