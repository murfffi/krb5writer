.DEFAULT_GOAL := test

.PHONY: test
test: tools/ts
	mkdir -p coverage/covdata
# Use the new binary format to ensure integration tests and cross-package calls are counted towards coverage
# https://go.dev/blog/integration-test-coverage
# -p 1 disable parallel testing in favor of streaming log output - https://github.com/golang/go/issues/24929#issuecomment-384484654
	go test -race -cover -covermode atomic -v -vet=all -timeout 15m -p 1\
		./... \
		-args -test.gocoverdir="${PWD}/coverage/covdata" \
		| tools/ts -s

	go tool covdata percent -i=./coverage/covdata
	# Convert to old text format for coveralls upload
	go tool covdata textfmt -i=./coverage/covdata -o ./coverage/covprofile
	go tool cover -html=./coverage/covprofile -o ./coverage/coverage.html

.PHONY: short-test
short-test:
	go test -v -short ./...

#NB: CI uses the golangci-lint Github action, not this target
.PHONY: lint
lint: tools/golangci-lint
	tools/golangci-lint run -v

.PHONY: checks
checks: check_tidy check_vuln check_modern

.PHONY: check_vuln
check_vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
# if we use more tools, we can switch to go tool -modfile=tools.mod
# there is good discussion at https://news.ycombinator.com/item?id=42845323

check_tidy:
	go mod tidy
	# Verify that `go mod tidy` didn't introduce any changes. Run go mod tidy before pushing.
	git diff --exit-code --stat go.mod go.sum

.PHONY: check_modern
check_modern:
	go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@v0.20.0 ./...
# non-zero exit status on issues found
# nb: modernize is not part of golangci-lint yet - https://github.com/golangci/golangci-lint/issues/686

# Tools targets

tools:
	mkdir -p tools

tools/ts: tools
# ts is a perl script. perl is installed on most linux systems, and in Ubuntu Github runners.
	curl -L -o tools/ts https://github.com/pgdr/moreutils/raw/a87889a3bf06fb6be6022b14c152f2f7de608910/ts
	@echo "96a9504920a81570e0fc5df9c7a8be76b043261d9ed4a702af0238bdbe5ad5ea  tools/ts" | sha256sum --check --strict
	chmod +x tools/ts

tools/golangci-lint: tools
# Version must be the same as in golangci-lint Github action
# We install golangci-lint as recommended in the docs. See the same docs for a discussion about go run and
# go get -tool alternatives - https://golangci-lint.run/docs/welcome/install/ .
# Delete tools/golangci-lint if this target is updated (may be automated in the future)
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b ./tools v2.5.0
