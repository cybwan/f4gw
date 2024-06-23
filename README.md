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

> **Client[192.168.226.21] <--> F4GW[192.168.226.22, 192.168.127.22] <--> F4Proxy[192.168.127.31] <--> Internet**

# TEST

## Client

```bash
curl http://httpbin.org -I

curl 18.208.239.112 -I

nslookup httpbin.org 8.8.8.8

ping 8.8.8.8
```

## F4GW

```bash
system=linux
arch=amd64
release=v0.8.1-kylinx.1
curl -L https://github.com/cybwan/f4gw/releases/download/${release}/f4gw-${release}-${system}-${arch}.tar.gz | tar -vxzf -
cd ./${system}-${arch}

# modify gw.json
./f4gw -c gw.json
```

## F4Proxy

```bash
system=linux
arch=amd64
release=v0.8.1-kylinx.1
curl -L https://github.com/cybwan/f4gw/releases/download/${release}/f4gw-${release}-${system}-${arch}.tar.gz | tar -vxzf -
cd ./${system}-${arch}

# modify proxy.json
./f4proxy -c proxy.json

# new terminal
pipy proxy.js
```

**Tracing log** (now disabled)

```
sudo cat /sys/kernel/debug/tracing/trace_pipe|grep bpf_trace_printk
```

nat netflow messages:

```
     ksoftirqd/0-14      [000] d.s21  7171.643922: bpf_trace_printk: ==================================
     ksoftirqd/0-14      [000] d.s21  7171.643949: bpf_trace_printk: f4m proto 17        ipv6(?) 0
     ksoftirqd/0-14      [000] d.s21  7171.643951: bpf_trace_printk: f4m daddr 8.8.8.8 dport 53
     ksoftirqd/0-14      [000] d.s21  7171.643953: bpf_trace_printk: f4m saddr 192.168.226.21 sport 39508
     ksoftirqd/0-14      [000] d.s21  7171.643953: bpf_trace_printk: f4m xaddr 192.168.127.22 xport 39508
          <idle>-0       [000] d.s31  7172.345965: bpf_trace_printk: ==================================
          <idle>-0       [000] dNs31  7172.345994: bpf_trace_printk: f4m proto 6         ipv6(?) 0
          <idle>-0       [000] dNs31  7172.345996: bpf_trace_printk: f4m daddr 18.208.239.112 dport 80
          <idle>-0       [000] dNs31  7172.345997: bpf_trace_printk: f4m saddr 192.168.226.21 sport 34706
          <idle>-0       [000] dNs31  7172.345997: bpf_trace_printk: f4m xaddr 192.168.127.22 xport 34706
```

**Nat Netflow**

```bash
bpftool map dump name f4gw_nat_opts
```

## TC

```
tc qdisc add dev lo clsact
tc filter add dev lo ingress bpf da obj ../tc_kern.o sec classifier/ingress
tc filter add dev lo egress  bpf da obj ../tc_kern.o sec classifier/egress
tc filter add dev lo ingress bpf object-pinned /sys/fs/bpf/bpf-sched-cls-test/demo
```

