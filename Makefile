BASE_DIR = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
INC_DIR = $(abspath ${BASE_DIR})/bpf/include
SRC_DIR = $(abspath ${BASE_DIR})/bpf/src
BIN_DIR = $(abspath ${BASE_DIR})/bin

XDP_GATEWAY_OUT = gateway.kern.o
XDP_GATEWAY_SRC = $(patsubst %.o,%.c,${XDP_GATEWAY_OUT})

XDP_PROXY_OUT = proxy.kern.o
XDP_PROXY_SRC = $(patsubst %.o,%.c,${XDP_PROXY_OUT})

F4GW_OUT = f4gw
F4PROXY_OUT = f4proxy

BPF_CFLAGS = \
	-O2 \
	-D__KERNEL__ \
	-DF4_DP_DEBUG_NTLB=1 \
	-DF4_DP_DEBUG_IF_=1   \
	-DF4_DP_DEBUG_CTRK_=1 \
	-DF4_DP_DEBUG_FCH4_=1 \
	-Wno-unused-value     \
	-Wno-pointer-sign     \
	-Wno-compare-distinct-pointer-types

.PHONY: bpf-fmt
bpf-fmt:
	find . -regex '.*\.\(c\|h\)' -exec clang-format -style=file -i {} \;

bpf-build: ${BIN_DIR}/${XDP_GATEWAY_OUT} ${BIN_DIR}/${XDP_PROXY_OUT}

${BIN_DIR}/${XDP_GATEWAY_OUT}: ${SRC_DIR}/${XDP_GATEWAY_SRC}
	clang -I${INC_DIR} ${BPF_CFLAGS} -emit-llvm -c -g $< -o - | llc -march=bpf -filetype=obj -o $@

${BIN_DIR}/${XDP_PROXY_OUT}: ${SRC_DIR}/${XDP_PROXY_SRC}
	clang -I${INC_DIR} ${BPF_CFLAGS} -emit-llvm -c -g $< -o - | llc -march=bpf -filetype=obj -o $@

bpf-clean:
	rm -f ${BIN_DIR}/${XDP_GATEWAY_OUT}
	rm -f ${BIN_DIR}/${XDP_PROXY_OUT}

.PHONY: go-fmt
go-fmt:
	go fmt ./...

.PHONY: go-generate
go-generate: export BPF_CFLAGS := $(BPF_CFLAGS)
go-generate: export BPF_INC_DIR := $(INC_DIR)
go-generate: export BPF_SRC_DIR := $(SRC_DIR)
go-generate:
	go generate ./...

.PHONY: go-build-f4gw
go-build-f4gw:
	go build -v -o ${BIN_DIR}/${F4GW_OUT} ./cmd/${F4GW_OUT}

.PHONY: go-build-f4proxy
go-build-f4proxy:
	go build -v -o ${BIN_DIR}/${F4PROXY_OUT} ./cmd/${F4PROXY_OUT}

.PHONY: go
go: go-generate
	go build -v -o ${BIN_DIR}/${F4GW_OUT} ./cmd/${F4GW_OUT}
	go build -v -o ${BIN_DIR}/${F4PROXY_OUT} ./cmd/${F4PROXY_OUT}

.PHONY: go-clean
go-clean:
	rm -f ${BIN_DIR}/${F4GW_OUT}
	rm -f ${BIN_DIR}/${F4PROXY_OUT}

f4gw-run: go
	${BIN_DIR}/${F4GW_OUT} -c ${BIN_DIR}/gw.json

f4proxy-run:
	${BIN_DIR}/${F4PROXY_OUT} -c ${BIN_DIR}/proxy.json

TARGETS := linux/amd64 linux/arm64
DIST_DIRS    := find * -type d -exec

GOPATH   = $(shell go env GOPATH)
GOBIN    = $(GOPATH)/bin
GOX      = go run github.com/mitchellh/gox
SHA256   = sha256sum
ifeq ($(shell uname),Darwin)
	SHA256 = shasum -a 256
endif

.PHONY: build-cross
build-cross:
	GO111MODULE=on CGO_ENABLED=0 $(GOX) -parallel=5 -output="_dist/{{.OS}}-{{.Arch}}/$(F4GW_OUT)" -osarch='$(TARGETS)' ./cmd/${F4GW_OUT}
	GO111MODULE=on CGO_ENABLED=0 $(GOX) -parallel=5 -output="_dist/{{.OS}}-{{.Arch}}/$(F4PROXY_OUT)" -osarch='$(TARGETS)' ./cmd/${F4PROXY_OUT}

.PHONY: dist
dist:
	( \
		cd _dist && \
		$(DIST_DIRS) cp ../LICENSE {} \; && \
		$(DIST_DIRS) cp ../README.md {} \; && \
		$(DIST_DIRS) cp ../bin/gw.json {} \; && \
		$(DIST_DIRS) cp ../bin/proxy.json {} \; && \
		$(DIST_DIRS) cp ../bin/proxy.pjs {} \; && \
		$(DIST_DIRS) tar -zcf f4gw-${VERSION}-{}.tar.gz {} \; && \
		$(DIST_DIRS) zip -r f4gw-${VERSION}-{}.zip {} \; && \
		$(SHA256) f4gw-* > sha256sums.txt \
	)

.PHONY: release-artifacts
release-artifacts: build-cross dist

.PHONY: release
VERSION_REGEXP := ^v[0-9]+\.[0-9]+\.[0-9]+(\-(alpha|beta|rc)\.[0-9]+)?$
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
