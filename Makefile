SHELL = bash

CC = gcc
CLANG = clang
GO = go
ARCH := $(shell uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')

BASE_DIR = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
INC_DIR = $(abspath ${BASE_DIR})/bpf/include
SRC_DIR = $(abspath ${BASE_DIR})/bpf/src
BIN_DIR = $(abspath ${BASE_DIR})/bin
BPF_DIR = $(abspath ${BASE_DIR})/bpf

XDP_GATEWAY_OUT = gateway.kern.o
XDP_GATEWAY_SRC = $(patsubst %.o,%.c,${XDP_GATEWAY_OUT})

F4GW_OUT = f4gw

BPF_CFLAGS = \
	-O2 \
	-D__KERNEL__ \
	-DLEGACY_BPF_MAPS=1 \
	-DF4_SPIN_LOCK_OFF=1 \
	-Wno-unused-value     \
	-Wno-pointer-sign     \
	-Wno-compare-distinct-pointer-types

CGO_CFLAGS_DYN = "-I. -I./bpf/include -I/usr/include/"
CGO_LDFLAGS_DYN = "-lelf -lz -lbpf"

.PHONY: bpf-fmt
bpf-fmt:
	find . -regex '.*\.\(c\|h\)' -exec clang-format -style=file -i {} \;

.PHONY: bpf-build
bpf-build: ${BIN_DIR}/${XDP_GATEWAY_OUT}

${BIN_DIR}/${XDP_GATEWAY_OUT}: ${SRC_DIR}/${XDP_GATEWAY_SRC}
	clang -I${INC_DIR} ${BPF_CFLAGS} -emit-llvm -c -g $< -o - | llc -march=bpf -filetype=obj -o $@

.PHONY: bpf-clean
bpf-clean:
	rm -f ${BIN_DIR}/${XDP_GATEWAY_OUT}

.PHONY: bpf
bpf: bpf-clean bpf-build

.PHONY: go-fmt
go-fmt:
	go fmt ./...

.PHONY: go-build-f4gw
go-build-f4gw: $(LIBBPF_OBJ)
	CC=$(CLANG) \
	CGO_CFLAGS=$(CGO_CFLAGS_DYN) \
	CGO_LDFLAGS=$(CGO_LDFLAGS_DYN) \
	GOOS=linux GOARCH=$(ARCH) \
	$(GO) build -o ${BIN_DIR}/${F4GW_OUT} ./cmd/${F4GW_OUT}

.PHONY: go
go: go-build-f4gw

.PHONY: go-clean
go-clean:
	rm -f ${BIN_DIR}/${F4GW_OUT}

f4gw-run: go
	${BIN_DIR}/${F4GW_OUT} -c ${BIN_DIR}/gw.json

TARGETS := linux/amd64 linux/arm64
DIST_DIRS    := find * -type d -exec

GOPATH   = $(shell go env GOPATH)
GOBIN    = $(GOPATH)/bin
GOX      = go run github.com/mitchellh/gox
SHA256   = sha256sum
ifeq ($(shell uname),Darwin)
	SHA256 = shasum -a 256
endif

.PHONY: dist
dist:
	( \
		mkdir -p _dist/linux-amd64 && cd _dist && \
		$(DIST_DIRS) cp ../LICENSE {} \; && \
		$(DIST_DIRS) cp ../README.md {} \; && \
		$(DIST_DIRS) cp ../bin/gw.json {} \; && \
		$(DIST_DIRS) cp ../bin/proxy.js {} \; && \
		$(DIST_DIRS) cp ../bin/gateway.kern.o {} \; && \
		$(DIST_DIRS) cp ../bin/f4gw {} \; && \
		$(DIST_DIRS) tar -zcf f4gw-${VERSION}-{}.tar.gz {} \; && \
		$(DIST_DIRS) zip -r f4gw-${VERSION}-{}.zip {} \; && \
		$(SHA256) f4gw-* > sha256sums.txt \
	)

.PHONY: release-artifacts
release-artifacts: dist

.PHONY: release
VERSION_REGEXP := ^v[0-9]+\.[0-9]+\.[0-9]+(\-(kylinx)\.[0-9]+)?$
release: ## Create a release tag, push to git repository and trigger the release workflow.
ifeq (,$(RELEASE_VERSION))
	$(error "RELEASE_VERSION must be set to tag HEAD")
endif
ifeq (,$(shell [[ "$(RELEASE_VERSION)" =~ $(VERSION_REGEXP) ]] && echo 1))
	$(error "Version $(RELEASE_VERSION) must match regexp $(VERSION_REGEXP)")
endif
	git tag --sign --message "fsm $(RELEASE_VERSION)" $(RELEASE_VERSION)
	git verify-tag --verbose $(RELEASE_VERSION)
	git push origin --tags
