SHELL = bash

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
	-DLEGACY_BPF_MAPS=1 \
	-DF4_SPIN_LOCK_OFF=1 \
	-DF4_DP_DEBUG_NTLB_=1 \
	-DF4_DP_DEBUG_IF_=1   \
	-DF4_DP_DEBUG_CTRK_=1 \
	-DF4_DP_DEBUG_FCH4_=1 \
	-Wno-unused-value     \
	-Wno-pointer-sign     \
	-Wno-compare-distinct-pointer-types

OUTPUT = ./bpf/lib

LIBBPF_SRC = $(abspath ./bpf/libbpf/src)
LIBBPF_OBJ = $(abspath ./$(OUTPUT)/libbpf.a)
LIBBPF_OBJDIR = $(abspath ./$(OUTPUT)/libbpf)
LIBBPF_DESTDIR = $(abspath ./$(OUTPUT))

CGO_CFLAGS_STATIC = "-I$(abspath $(OUTPUT))"
CGO_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_OBJ)"
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'

CGO_CFGLAGS_DYN = "-I. -I/usr/include/"
CGO_LDFLAGS_DYN = "-lelf -lz -lbpf"

.PHONY: libbpf-static
libbpf-static: $(LIBBPF_OBJ)

$(LIBBPF_OBJ): $(LIBBPF_SRC) $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(OUTPUT)/libbpf
	CC="$(CC)" CFLAGS="$(CFLAGS)" LD_FLAGS="$(LDFLAGS)" \
	   $(MAKE) -C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_OBJDIR) \
		DESTDIR=$(LIBBPF_DESTDIR) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

$(LIBBPF_SRC):
ifeq ($(wildcard $@), )
	echo "INFO: updating submodule 'libbpf'"
	wget https://github.com/libbpf/libbpf/archive/refs/tags/v0.8.3.tar.gz
	tar zxf v0.8.3.tar.gz
	mv libbpf-0.8.3 ./bpf/libbpf
	rm -rf v0.8.3.tar.gz
endif

# output

$(OUTPUT):
	mkdir -p $(OUTPUT)

$(OUTPUT)/libbpf:
	mkdir -p $(OUTPUT)/libbpf

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
		$(DIST_DIRS) cp ../bin/proxy.js {} \; && \
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
