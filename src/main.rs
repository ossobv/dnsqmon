//! dnsqmon: count DNS queries per (source IP, qname, qtype) and emit periodic
//! summaries. Intended to run as a DaemonSet on k8s nodes where NAT/masquerade
//! obscures the real client on the upstream side.
//!
//! Capture uses `any` pseudo-device so pod-side interfaces (cilium_*, lxc*,
//! veth*) are included. A small dedup window suppresses duplicates caused by
//! the same packet being seen on multiple interfaces as it traverses the stack.

use std::collections::HashMap;
use std::net::IpAddr;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use dns_parser::Packet as DnsPacket;
use serde::Serialize;

/// Version string. Inside Docker (`.git` not available) we rely on the
/// `version-from-env` feature and read GIT_VERSION from the build env; for
/// local `cargo build` the `git_version!()` macro reads `git describe` at
/// compile time. Same pattern as ossobv/natsomatch.
#[cfg(feature = "version-from-env")]
const GIT_VERSION: &str = env!("GIT_VERSION");
#[cfg(not(feature = "version-from-env"))]
const GIT_VERSION: &str = git_version::git_version!(
    args = ["--always", "--dirty", "--tags"],
    fallback = "unknown"
);

/// Set by the SIGTERM/SIGINT handler. Main loop checks this each iteration
/// and exits after a final flush.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Set by the SIGUSR1 handler. Main loop checks this and emits a summary
/// immediately, then resets the flag and continues. Useful for on-demand
/// snapshots during investigation without waiting for the flush interval.
static FLUSH_NOW: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(sig: libc::c_int) {
    // Only signal-safe thing we do: one atomic store. No allocation, no
    // stdio, no locks.
    match sig {
        libc::SIGUSR1 => FLUSH_NOW.store(true, Ordering::Relaxed),
        _ => SHUTDOWN.store(true, Ordering::Relaxed),
    }
}

fn install_signal_handlers() -> std::io::Result<()> {
    // SAFETY: sigaction with a minimal handler is signal-safe. The handler
    // only touches an AtomicBool; no locks, no allocations, no syscalls that
    // could deadlock us.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_signal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        // No SA_RESTART: we want poll() to return with EINTR so the main
        // loop sees the shutdown/flush flag promptly.
        sa.sa_flags = 0;
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGUSR1] {
            if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    unsafe {
        // Restore default SIGPIPE handling (kernel terminates us silently).
        // Rust ignores SIGPIPE by default, which turns broken-pipe writes into
        // panics on println!. Having the kernel kill us is what every other
        // Unix tool does and matches what users expect from `prog | head`.
        let mut dfl: libc::sigaction = std::mem::zeroed();
        dfl.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut dfl.sa_mask);
        libc::sigaction(libc::SIGPIPE, &dfl, std::ptr::null_mut());
    }
    Ok(())
}

#[derive(Parser, Debug)]
#[command(
    about = "Sniff DNS queries and emit periodic summaries",
    version = GIT_VERSION,
)]
struct Args {
    /// Capture device. Use "any" on Linux to catch all interfaces including
    /// cilium_*, lxc*, veth*.
    #[arg(short = 'i', long, default_value = "any")]
    iface: String,

    /// UDP ports for DNS traffic. Repeat the flag (-p 53 -p 5353) or pass a
    /// comma-separated list (-p 53,5353,5300). At least one port is required;
    /// default is 53.
    #[arg(
        short = 'p',
        long = "port",
        value_delimiter = ',',
        default_values_t = [53u16],
    )]
    ports: Vec<u16>,

    /// Flush interval in seconds.
    #[arg(short = 'f', long, default_value_t = 60)]
    flush_secs: u64,

    /// Output format.
    #[arg(long, default_value = "json")]
    format: OutputFormat,
}

/// Dedup window. The same (src_ip, src_port, dns_id) observed within this
/// window -- typically because `-i any` saw the same packet cross multiple
/// interfaces -- is counted once. 200ms is plenty: legitimate retransmits with
/// the same transaction ID are rare and usually slower than this.
const DEDUP_MS: u64 = 200;

/// Dedup at least.
const DEDUP_MIN_S: u64 = 15;

#[derive(Debug, Clone, clap::ValueEnum)]
enum OutputFormat {
    Json,
    Text,
}

/// Key for aggregation. Tuple of what we want to break summaries down by.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct AggKey {
    src_ip: IpAddr,
    qname: String,
    qtype: u16,
}

#[derive(Debug)]
struct AggValue {
    count: u64,
    first_seen: SystemTime,
    last_seen: SystemTime,
}

/// Summary record as emitted on flush. Borrows from the aggregation so we
/// don't clone qname / src_ip per row.
#[derive(Serialize)]
struct Summary<'a> {
    // We could print the window size, but it's not very useful.
    //window_start: u64,
    //window_end: u64,
    src_ip: IpAddr,
    qname: &'a str,
    qtype: &'a str,
    count: u64,
    first_seen: u64,
    last_seen: u64,
}

/// Key used for dedup. DNS transaction IDs plus ephemeral source port are
/// very unlikely to collide for the same client within a 1s window.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct DedupKey {
    src_ip: IpAddr,
    src_port: u16,
    dns_id: u16,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    install_signal_handlers()?;

    if args.ports.is_empty() {
        return Err("at least one -p/--port is required".into());
    }

    // Build BPF filter. Kernel filters mean we never see non-matching packets
    // in userspace. libpcap compiles this to eBPF; a handful of port terms is
    // fine, the filter engine short-circuits on mismatch.
    let filter = args
        .ports
        .iter()
        .map(|p| format!("udp port {}", p))
        .collect::<Vec<_>>()
        .join(" or ");

    // Stderr for version? Makes sense when we do JSON for all stdout.
    eprintln!(
        "dnsqmon {}\ndnsqmon: iface={} filter=\"{}\" flush={}s dedup={}ms",
        GIT_VERSION, args.iface, filter, args.flush_secs, DEDUP_MS
    );

    let cap = pcap::Capture::from_device(args.iface.as_str())?
        // No immediate_mode: let the kernel batch packets into its ring buffer.
        // We drain in bursts when we poll. Cheaper under load (fewer wakeups)
        // and flush timing is driven by our own loop, not libpcap wakeups.
        .snaplen(2048)        // DNS queries fit easily; this caps memory per packet
        .timeout(1000)        // ms; only a fallback -- we drive flush timing ourselves
        .open()?;

    // Non-blocking mode: next_packet() returns NoMorePackets immediately when
    // the ring is empty rather than blocking. This decouples flush timing from
    // packet arrival -- libpcap's read timeout is documented as unreliable and
    // in practice only fires when at least one packet has been buffered, so we
    // can't rely on it to wake us up for the periodic flush.
    let mut cap = cap.setnonblock()?;
    cap.filter(&filter, true)?;

    // Detect link-layer header length once. `-i any` on Linux yields
    // LINKTYPE_LINUX_SLL (16-byte header) on older libpcap and
    // LINKTYPE_LINUX_SLL2 (20-byte header) on newer. Regular interfaces give
    // Ethernet (14 bytes). The value is fixed for the life of the capture,
    // so we compute offsets once and skip the per-packet heuristic.
    let link_type = cap.get_datalink();
    let l2_len = match link_type.0 {
        1 => 14,   // DLT_EN10MB (Ethernet)
        113 => 16, // DLT_LINUX_SLL
        276 => 20, // DLT_LINUX_SLL2
        other => {
            return Err(format!(
                "unsupported datalink type {} on {}; only Ethernet, SLL, SLL2 are handled",
                other, args.iface
            )
            .into());
        }
    };
    eprintln!("dnsqmon: datalink={} l2_len={}", link_type.0, l2_len);

    // Capacity hints: we expect a couple hundred unique (src, qname, qtype)
    // combinations per flush window on a busy node. Preallocating avoids the
    // early rehash/grow cycle showing up as mmap churn in strace. If the
    // working set grows past this, HashMap will rehash -- fine, just rare.
    let mut agg: HashMap<AggKey, AggValue> = HashMap::with_capacity(512);
    let mut dedup: HashMap<DedupKey, Instant> = HashMap::with_capacity(1024);
    // Scratch buffer for flush sorting, reused across flushes.
    let mut flush_scratch: Vec<(AggKey, AggValue)> = Vec::with_capacity(512);
    let dedup_window = Duration::from_millis(DEDUP_MS);
    let flush_interval = Duration::from_secs(args.flush_secs);

    let mut window_start = SystemTime::now();
    let mut last_flush = Instant::now();
    let mut last_dedup_gc = Instant::now();

    // Raw fd for poll(). libpcap's selectable fd blocks in the kernel until a
    // packet is ready or the timeout fires -- no userspace busy-looping.
    let pcap_fd = cap.as_raw_fd();

    loop {
        // Compute time until the next thing we need to do (flush or dedup GC).
        let now = Instant::now();
        let until_flush = flush_interval.saturating_sub(now.duration_since(last_flush));
        let until_gc = Duration::from_secs(DEDUP_MIN_S)
            .saturating_sub(now.duration_since(last_dedup_gc));
        let wait = until_flush.min(until_gc);

        // Block in the kernel until a packet arrives or the timer expires.
        // poll() is a single syscall; this is the idle path -- zero CPU when
        // nothing is happening.
        let wait_ms = wait.as_millis().min(i32::MAX as u128) as i32;
        let mut pfd = libc::pollfd {
            fd: pcap_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, wait_ms) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            // EINTR just means a signal interrupted us; loop and re-check timers.
            if err.raw_os_error() != Some(libc::EINTR) {
                eprintln!("poll error: {}", err);
            }
        }

        // Drain all ready packets in one go. setnonblock() guarantees
        // next_packet() returns NoMorePackets rather than blocking once the
        // ring is empty.
        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    // Kernel-supplied capture timestamp. More accurate than
                    // reading the wall clock in userspace, and it lines up
                    // with what tcpdump would show.
                    let ts = timeval_to_system_time(&packet.header.ts);

                    if let Some((src_ip, src_port, dns_payload)) = parse_udp(packet.data, l2_len) {
                        if let Ok(dns) = DnsPacket::parse(dns_payload) {
                            // Queries only (QR=0). Responses would inflate counts.
                            if dns.header.query && !dns.questions.is_empty() {
                                let dns_id = dns.header.id;

                                // Dedup: first sighting within window wins.
                                let dk = DedupKey { src_ip, src_port, dns_id };
                                let now_i = Instant::now();
                                let is_dup = match dedup.get(&dk) {
                                    Some(seen_at) => {
                                        now_i.duration_since(*seen_at) < dedup_window
                                    }
                                    None => false,
                                };
                                dedup.insert(dk, now_i);

                                if !is_dup {
                                    for q in &dns.questions {
                                        let key = AggKey {
                                            src_ip,
                                            qname: q.qname.to_string(),
                                            qtype: q.qtype as u16,
                                        };
                                        agg.entry(key)
                                            .and_modify(|v| {
                                                v.count += 1;
                                                v.last_seen = ts;
                                            })
                                            .or_insert(AggValue {
                                                count: 1,
                                                first_seen: ts,
                                                last_seen: ts,
                                            });
                                    }
                                }
                            }
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) | Err(pcap::Error::NoMorePackets) => {
                    // Ring drained; go back to poll().
                    break;
                }
                Err(e) => {
                    eprintln!("capture error: {}", e);
                    break;
                }
            }
        }

        // Periodic flush, or on-demand via SIGUSR1. We check the flag with
        // swap() so a burst of USR1s collapses to a single extra flush.
        let signaled_flush = FLUSH_NOW.swap(false, Ordering::Relaxed);
        if signaled_flush || last_flush.elapsed() >= flush_interval {
            if signaled_flush {
                eprintln!("dnsqmon: SIGUSR1 received, flushing");
            }
            flush(
                &mut agg,
                &mut flush_scratch,
                window_start,
                SystemTime::now(),
                &args.format,
            );
            window_start = SystemTime::now();
            last_flush = Instant::now();
        }

        // GC dedup table so it doesn't grow forever.
        if last_dedup_gc.elapsed() >= Duration::from_secs(5) {
            let now_i = Instant::now();
            dedup.retain(|_, seen_at| now_i.duration_since(*seen_at) < dedup_window);
            last_dedup_gc = now_i;
        }

        // SIGTERM/SIGINT: emit one last summary and exit cleanly. Without
        // this, kubelet's 30s grace period would discard whatever was in the
        // current window.
        if SHUTDOWN.load(Ordering::Relaxed) {
            eprintln!("dnsqmon: shutdown signal received, flushing and exiting");
            flush(
                &mut agg,
                &mut flush_scratch,
                window_start,
                SystemTime::now(),
                &args.format,
            );
            return Ok(());
        }
    }
}

/// Parse a captured frame: skip the link-layer header, then IPv4/IPv6 + UDP.
/// Returns (src_ip, src_port, udp_payload).
///
/// `l2_len` is the link-layer header length determined at capture-open time
/// from the datalink type (14 for Ethernet, 16 for SLL, 20 for SLL2).
///
/// We deliberately parse by hand rather than pulling in `etherparse` or
/// `pnet` -- DNS-over-UDP parsing is small and the deps aren't worth it.
fn parse_udp(data: &[u8], l2_len: usize) -> Option<(IpAddr, u16, &[u8])> {
    if data.len() < l2_len + 20 {
        return None;
    }
    let ip = &data[l2_len..];
    match ip[0] >> 4 {
        4 => parse_ipv4(ip),
        6 => parse_ipv6(ip),
        _ => None,
    }
}

fn parse_ipv4(data: &[u8]) -> Option<(IpAddr, u16, &[u8])> {
    if data.len() < 20 {
        return None;
    }
    let ihl = (data[0] & 0x0f) as usize * 4;
    if ihl < 20 || data.len() < ihl + 8 {
        return None;
    }
    let proto = data[9];
    if proto != 17 {
        return None; // UDP only
    }
    let src = IpAddr::from([data[12], data[13], data[14], data[15]]);
    let udp = &data[ihl..];
    parse_udp_payload(src, udp)
}

fn parse_ipv6(data: &[u8]) -> Option<(IpAddr, u16, &[u8])> {
    if data.len() < 40 {
        return None;
    }
    let next_header = data[6];
    if next_header != 17 {
        // We ignore packets with v6 extension headers. DNS-over-UDP in
        // practice doesn't use them; adding a walker is more code for
        // little gain.
        return None;
    }
    let mut src = [0u8; 16];
    src.copy_from_slice(&data[8..24]);
    let udp = &data[40..];
    parse_udp_payload(IpAddr::from(src), udp)
}

fn parse_udp_payload(src_ip: IpAddr, udp: &[u8]) -> Option<(IpAddr, u16, &[u8])> {
    if udp.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    Some((src_ip, src_port, &udp[8..]))
}

/// Map a DNS QTYPE number to a short name. Falls back to `TYPExxx` notation
/// (the RFC3597 convention) for values we don't special-case, so unusual
/// query types stay distinguishable in output rather than all collapsing to
/// "OTHER".
fn qtype_str(q: u16) -> String {
    match q {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        35 => "NAPTR".into(),
        43 => "DS".into(),
        46 => "RRSIG".into(),
        47 => "NSEC".into(),
        48 => "DNSKEY".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        99 => "SPF".into(),
        255 => "ANY".into(),
        257 => "CAA".into(),
        n => format!("TYPE{}", n),
    }
}

fn flush(
    agg: &mut HashMap<AggKey, AggValue>,
    scratch: &mut Vec<(AggKey, AggValue)>,
    window_start: SystemTime,
    window_end: SystemTime,
    format: &OutputFormat,
) {
    if agg.is_empty() {
        return;
    }

    let ws = unix_secs(window_start);
    let we = unix_secs(window_end);

    // Reuse `scratch` across flushes so we don't allocate a fresh Vec each
    // time. `agg.drain()` empties the map but keeps its bucket array, so the
    // map also doesn't reallocate on steady-state traffic.
    scratch.clear();
    scratch.extend(agg.drain());
    scratch.sort_by(|a, b| b.1.count.cmp(&a.1.count));

    match format {
        OutputFormat::Json => {
            for (k, v) in scratch.iter() {
                let qtype_name = qtype_str(k.qtype);
                let s = Summary {
                    //window_start: ws,
                    //window_end: we,
                    src_ip: k.src_ip,
                    qname: &k.qname,
                    qtype: &qtype_name,
                    count: v.count,
                    first_seen: unix_secs(v.first_seen),
                    last_seen: unix_secs(v.last_seen),
                };
                // One JSON object per line -- easy to ingest into Loki/ES.
                println!("{}", serde_json::to_string(&s).unwrap());
            }
        }
        OutputFormat::Text => {
            println!("--- window {} -> {} ({} entries) ---", ws, we, scratch.len());
            for (k, v) in scratch.iter() {
                println!(
                    "{:>8}  {:<39}  {:<6}  {}  (first={} last={})",
                    v.count,
                    k.src_ip,
                    qtype_str(k.qtype),
                    k.qname,
                    unix_secs(v.first_seen),
                    unix_secs(v.last_seen),
                );
            }
        }
    }
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Convert a libpcap `timeval` (kernel-stamped capture time) to `SystemTime`.
/// `tv_sec` / `tv_usec` widths vary by platform (i64 on Linux glibc, i32 on
/// some others), hence the `as` casts.
fn timeval_to_system_time(tv: &libc::timeval) -> SystemTime {
    let secs = tv.tv_sec as u64;
    let nsecs = (tv.tv_usec as u32).saturating_mul(1000);
    UNIX_EPOCH + Duration::new(secs, nsecs)
}
