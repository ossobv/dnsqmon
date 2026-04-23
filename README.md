# dnsqmon

Small Rust DNS query sniffer. Aggregates by (source IP, qname, qtype) and
emits periodic summaries to stdout. Built to run as a DaemonSet on k8s nodes
where NAT masks the real source of DNS queries on upstream recursors.

## Why on the node, not the recursor

On the recursor you only see post-NAT IPs. Running on the k8s node with
`-i any` means you see traffic on `cilium_*` / `lxc*` / `veth*` interfaces
where the pod's real IP is still intact, before masquerade.

## How duplicates are avoided

`-i any` shows the same packet once per interface it crosses (pod veth, host
veth, cilium\_host, eth0...). Dedup key is `(src_ip, src_port, dns_id)` with
a 200ms window. DNS transaction IDs + ephemeral ports make collisions within
that window essentially impossible for the same client.

## Build

Local:

    cargo build --release

Container:

    ./build-docker.sh

    version=$(git describe --always --dirty=+modified |
              sed -e 's/[^A-Za-z0-9.-]\+/_/g')
    docker tag build-dnsqmon:$version your-repository/dnsqmon:$version
    docker push your-registry/dnsqmon:$version

## Run

Standalone (needs root or `CAP_NET_RAW`):

    sudo ./target/release/dnsqmon -i any -p 53 -f 60

Multiple ports (repeat `-p` or pass a comma-separated list):

    sudo ./target/release/dnsqmon -i any -p 53 -p 5353
    sudo ./target/release/dnsqmon -i any -p 53,5353,5300

Output is one JSON object per (`src_ip`, `qname`, `qtype`) per flush window.
Pipe into whatever log shipper you have.

## Signals

- `SIGUSR1`: emit a summary immediately without waiting for the flush
  interval. Useful during investigation -- no need to lower `-f` and restart.
  Example: `kill -USR1 $(pidof dnsqmon)`.
- `SIGTERM` / `SIGINT`: emit a final summary and exit cleanly. Kubelet sends
  SIGTERM on pod shutdown; without this, the in-flight window would be lost.

## Deploy

    kubectl apply -f daemonset.yaml

Then tail:

    kubectl -n kube-system logs -l app=dnsqmon -f --max-log-requests 20

## Sample output

    {"src_ip":"10.244.1.37",
     "qname":"suspicious.example.com","qtype":"A","count":14,
     "first_seen":1713868803,"last_seen":1713868859}

## Limitations

- IPv6 extension headers are not walked. DNS-over-UDP in practice doesn't use
  them. If you need it, parse the next-header chain in `parse_ipv6`.
- UDP only. TCP DNS (large responses, AXFR) is ignored. Adjust the BPF filter
  and add a TCP reassembly path if needed -- for a query-source investigation
  it's rarely worth the complexity.
- Single-threaded. At very high pps (>50k) you'd want a thread to drain
  packets and another to aggregate, connected by a channel.
- Flush interval might be delayed by 1-2 seconds, because we use efficient
  kernel buffering.
- A single lookup might look like 4 queries, for instance when both A and AAAA
  are qierues up *and* NAT-translation is performed on the host:
  - `{"src_ip":"POD_IP","qname":"example.com","qtype":"A","count":1,...}`
  - `{"src_ip":"NODE_IP","qname":"example.com","qtype":"A","count":1,...}`
  - `{"src_ip":"POD_IP","qname":"example.com","qtype":"AAAA","count":1,...}`
  - `{"src_ip":"NODE_IP","qname":"example.com","qtype":"AAAA","count":1,...}`
  This is not a bug.
- Right now, we dump a big batch of data every flush-period. We might instead
  opt to do the following:
  - When a query arrives we dump it immediately and then store it in a hashmap.
  - When another query with the same (src,qname,qtype) tuple arrives, it is
    only added to the map and not printed.
  - After flush-period for that particular record, the totals are printed and
    the map is cleared of that record. This would result in:
    - t=0  example.com, count=1
    - t=60 example.com, count=59
    - t=61 example.com, count=1
    - t=120 example.com, count=59
    Advantage: no big log batches, and immediate output for single queries.
    Disadvantage: twice the output (count=1), unless we can be smart about
    dumping when flushing.
