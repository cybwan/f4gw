# F4GW

# TOPO

**Client[192.168.226.21] <--> F4GW[192.168.226.22, 192.168.127.22] <--> F4Proxy[192.168.127.31] <--> Internet**

# TEST

## Client

```bash
curl http://httpbin.org -I

nslookup httpbin.org 8.8.8.8

ping www.baidu.com
```

## F4GW

```bash
./f4gw -c gw.json
```

## F4Proxy

```bash
./f4proxy -c proxy.json
```

**Tracing log**

```
sudo cat /sys/kernel/debug/tracing/trace_pipe|grep bpf_trace_printk
```
