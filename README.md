# F4GW

# Prerequisites

> **kylinx v10 sp3**

```bash
yum install bpftool -y
yum install libbpf libbpf-devel -y
```

# Compile Prerequisites

```bash
yum install make -y
yum install clang -y
yum install llvm -y

cd /opt
wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
tar zxf go1.22.4.linux-amd64.tar.gz
export PATH=/opt/go/bin:$PATH
go env -w GOPROXY=https://goproxy.cn
go env -w GOROOT=/opt/go
go env -w GOPATH=~/go
mkdir ~/go
```

# TOPO

> **Client[192.168.226.21] <--> F4GW[192.168.226.22, 192.168.127.22] <--> Internet**

# TEST

## Client

```bash
curl http://httpbin.org -I

nslookup httpbin.org 8.8.8.8

ping 8.8.8.8
```

## F4GW

```bash
system=linux
arch=amd64
release=v0.1.1-kylinx.1
curl -L https://github.com/cybwan/f4gw/releases/download/${release}/f4gw-${release}-${system}-${arch}.tar.gz | tar -vxzf -
cd ./${system}-${arch}

# modify gw.json
./f4gw -c gw.json

# new terminal
pipy proxy.js
```

**Nat Netflow**

```bash
bpftool map dump name f4gw_nat_opts
```
