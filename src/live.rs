//! The firewall's live state, and the one seam it comes through.
//!
//! What the engine is doing — which sockets listen and who owns them, the
//! connections it has judged and the sentence on each, its counters, and
//! its verdict stream — is read from `/dev/peios-ntfe`. That device is the
//! kernel's alone for now (mode 0600, one reader of the stream, no
//! management interface over it: PEI-598's layer 2), so until a program
//! like this one may read it, [`read`] makes **example data**, in exactly
//! the records the device gives ([`ntfe`]), and says so ([`Live::example`]).
//! Phase 2 replaces the body of [`read`] with reads of the device; nothing
//! else changes.
//!
//! The example is made from this machine where it can be: its interfaces'
//! own addresses, the desktop connections really open now, and verdicts
//! judged by the machine's real rules, so what it shows agrees with
//! everything else on the screen.

use std::net::{IpAddr, Ipv4Addr};

use ntfe::{Counter, Direction, Endpoint, EndpointKind, Event, Flow, KeySpec, Listener, Sentence, Slot};

use crate::engine::{self, Conn, Judge};
use crate::machine::{Config, State};
use crate::rules::{self, Verdict};

/// The engine as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Engine {
    /// The policy generation in force.
    pub generation: u64,
    /// Changes written and not yet walked.
    pub pending: bool,
    /// Why the last walk was refused, as an errno, while the previous
    /// generation stands.
    pub refusal: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct Live {
    pub engine: Engine,
    pub listeners: Vec<Listener>,
    pub flows: Vec<Flow>,
    pub counters: Vec<Counter>,
    /// The verdict stream, oldest first.
    pub events: Vec<Event>,
    /// Example data, not the machine's.
    pub example: bool,
}

/// Services a socket's owner is recognised as, by its service SID.
const SERVICES: &[&str] = &["sshd", "gxwid", "resolvd", "pnpd", "netd", "timed", "peipkg", "atriumd", "authd", "eventd"];

/// The service a program endpoint runs as, by name.
pub fn service(endpoint: &Endpoint) -> Option<&'static str> {
    let sid = endpoint.service.as_deref()?;
    SERVICES.iter().copied().find(|name| pnp_core::Sid::service(name).as_bytes() == sid)
}

fn owner(service: Option<&str>, comm: &str, pid: i32) -> Endpoint {
    match service {
        Some(name) => Endpoint {
            kind: EndpointKind::Program,
            unresolved: false,
            pid,
            guid: [0; 16],
            comm: comm.into(),
            user: Some(pnp_core::Sid::well_known("LocalService").unwrap_or_default().as_bytes().to_vec()),
            service: Some(pnp_core::Sid::service(name).as_bytes().to_vec()),
        },
        None => Endpoint { kind: EndpointKind::None, unresolved: false, pid: 0, guid: [0; 16], comm: String::new(), user: None, service: None },
    }
}

/// What a listener is, for a person.
pub fn listener_title(listener: &Listener) -> String {
    match service(&listener.owner) {
        Some("sshd") => "SSH".into(),
        Some("gxwid") => "Web desktop".into(),
        Some("resolvd") => "DNS stub resolver".into(),
        Some("pnpd") => "PNP viewer (development)".into(),
        Some("atriumd") => "Atrium (development)".into(),
        Some(other) => other.into(),
        None => listener.owner.comm.clone(),
    }
}

/// Whether a listener takes connections only from this machine.
pub fn loopback_only(listener: &Listener) -> bool {
    listener.addr.is_some_and(|a| a.is_loopback())
}

pub fn protocol_name(number: u8) -> &'static str {
    match number {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        58 => "icmpv6",
        132 => "sctp",
        _ => "ip",
    }
}

fn number(protocol: &str) -> u8 {
    match protocol {
        "tcp" => 6,
        "udp" => 17,
        "icmp" => 1,
        "icmpv6" => 58,
        _ => 132,
    }
}

/// A flow as a connection the rules judge: what "Why?" asks about.
pub fn conn(flow: &Flow, config: &Config, state: &State) -> Conn {
    let inbound = flow.direction != Some(Direction::Out);
    let interface = if flow.loopback {
        "lo".to_string()
    } else {
        state.interfaces.iter().find(|i| Some(i.status.index as i32) == flow.ifindex).map(|i| i.status.name.clone()).unwrap_or_else(|| "eth0".into())
    };
    let network = state.interface(&interface).map(|i| i.subject(config).network).unwrap_or_default();
    let (local, remote, local_port, remote_port) = if inbound { (flow.dst, flow.src, flow.dst_port, flow.src_port) } else { (flow.src, flow.dst, flow.src_port, flow.dst_port) };
    let owner = flow.owner();
    Conn {
        inbound,
        protocol: protocol_name(flow.protocol).into(),
        remote: remote.map(|a| a.to_string()).unwrap_or_default(),
        remote_port,
        local: local.map(|a| a.to_string()).unwrap_or_default(),
        local_port,
        interface,
        network,
        service: owner.and_then(service).map(str::to_string),
        established: flow.seen_reply,
    }
}

/// The counter value a rule's view would read for `conn`: a cell of the
/// view's stream whose key the connection has, at the view's window.
pub fn count(counters: &[Counter], view: &pnp_core::CounterView, conn: &Conn) -> Option<u64> {
    let want = KeySpec {
        src_addr: view.keyspec & pnp_core::keyspec::SRC_ADDR != 0,
        dst_addr: view.keyspec & pnp_core::keyspec::DST_ADDR != 0,
        interface: view.keyspec & pnp_core::keyspec::INTERFACE != 0,
    };
    let (src, dst): (Option<IpAddr>, Option<IpAddr>) = if conn.inbound { (conn.remote.parse().ok(), conn.local.parse().ok()) } else { (conn.local.parse().ok(), conn.remote.parse().ok()) };
    let cell = counters.iter().find(|c| c.name == view.name.as_str() && c.keyspec == want && (!want.src_addr || c.src == src) && (!want.dst_addr || c.dst == dst))?;
    if view.window_secs == 0 {
        return Some(cell.total);
    }
    cell.windows.iter().find(|(w, _)| *w == view.window_secs).map(|(_, v)| *v)
}

/// A small, steady pseudo-random number for `seed`: the example changes
/// minute by minute, not render by render.
fn wobble(seed: u64, span: u64) -> u64 {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0xd1b5_4a32_d192_ed03;
    x ^= x >> 29;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 32;
    x % span.max(1)
}

/// Another address on the same /24 as `addr`.
fn neighbour(addr: Ipv4Addr, last: u8) -> Ipv4Addr {
    let o = addr.octets();
    Ipv4Addr::new(o[0], o[1], o[2], last)
}

fn v4(text: &str) -> Option<Ipv4Addr> {
    text.split('/').next()?.parse().ok()
}

/// The firewall's live state. Example data: see the module's comment.
pub fn read(config: &Config, state: &State, generation: u64) -> Live {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let minute = now / 60;
    let iface = state.online().or(state.interfaces.first());
    let ifindex = iface.map(|i| i.status.index as i32).unwrap_or(2);
    let here = iface.and_then(|i| i.status.addresses.iter().find_map(|a| v4(a))).unwrap_or(Ipv4Addr::new(192, 168, 1, 40));
    let gateway = iface.and_then(|i| i.status.gateway.as_deref()).and_then(v4).unwrap_or(neighbour(here, 1));
    let dns = iface.and_then(|i| i.status.dns.first()).and_then(|d| v4(d)).unwrap_or(gateway);

    let listener = |service: &str, comm: &str, protocol: u8, port: u16, addr: Option<IpAddr>, pid: i32| Listener {
        protocol,
        port,
        addr,
        ifindex: None,
        reuseport: false,
        connected: false,
        v6only: false,
        owner: owner(Some(service), comm, pid),
    };
    let stub = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)));
    let listeners = vec![
        listener("sshd", "sshd", 6, 22, None, 412),
        listener("gxwid", "gxwid", 6, config.desktop_port, None, 388),
        listener("resolvd", "resolvd", 17, 53, stub, 301),
        listener("resolvd", "resolvd", 6, 53, stub, 301),
        listener("pnpd", "pnpd", 6, 8081, None, 455),
    ];

    // (inbound, protocol, remote, remote port, local port, service, age in
    // seconds, bytes each way)
    type Shape<'a> = (bool, u8, IpAddr, u16, u16, Option<&'a str>, u64, [u64; 2]);
    let flood = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
    let peer = IpAddr::V4(neighbour(here, 31));
    let mut shapes: Vec<Shape> = vec![
        (true, 6, peer, 40122, 22, Some("sshd"), 360, [98_000, 114_000]),
        (true, 6, flood, 58210, 22, Some("sshd"), 2, [180, 0]),
        (true, 6, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 49311, 3389, None, 8, [60, 0]),
        (false, 17, IpAddr::V4(dns), 53, 41877, Some("resolvd"), 1, [82, 82]),
        (false, 6, IpAddr::V4(Ipv4Addr::new(151, 101, 2, 132)), 443, 52210, Some("peipkg"), 12, [600_000, 41_000_000]),
        (false, 17, IpAddr::V4(Ipv4Addr::new(162, 159, 200, 1)), 123, 38001, Some("timed"), 180, [90, 90]),
    ];
    // The desktop's own connections are real.
    for s in &state.sessions {
        if let Ok(remote) = s.remote.parse() {
            shapes.insert(0, (true, 6, remote, s.remote_port, s.local_port, Some("gxwid"), 2460, [2_100_000, 18_400_000]));
        }
    }

    // Counters: every stream a rule counts into, with a cell per source of
    // the incoming example connections, and the windows the rules read.
    let mut streams: Vec<String> = Vec::new();
    let mut windows: Vec<u32> = vec![60];
    for layer in rules::Layer::FIREWALL {
        for (_, _, rule) in rules::walk(config.policy.forest(layer)) {
            for action in &rule.actions {
                if let Some((name, args)) = rules::call(action)
                    && name.eq_ignore_ascii_case("COUNT")
                    && let Some(stream) = args.first()
                    && !streams.iter().any(|s| s == stream)
                {
                    streams.push(stream.to_string());
                }
            }
            for cond in &rule.conds {
                if let Some(spec) = cond.fact.strip_prefix("Counter.")
                    && let Ok(view) = pnp_core::CounterView::parse(spec)
                    && view.window_secs > 0
                    && !windows.contains(&view.window_secs)
                {
                    windows.push(view.window_secs);
                }
            }
        }
    }
    let mut counters = Vec::new();
    for (n, stream) in streams.iter().enumerate() {
        let per_minute = |src: Option<IpAddr>| match src {
            Some(a) if a == flood => 14,
            Some(_) => 1,
            None => 15 + wobble(minute + n as u64, 6),
        };
        let cell = |src: Option<IpAddr>, keyspec: KeySpec| {
            let rate = per_minute(src);
            Counter {
                name: stream.clone(),
                hash: ntfe::rule_hash(stream),
                keyspec,
                interface: None,
                src,
                dst: None,
                total: 380 + rate * 9 + wobble(n as u64, 40),
                last_secs: now - 1,
                windows: windows.iter().map(|w| (*w, rate * u64::from(*w) / 60)).collect(),
            }
        };
        counters.push(cell(None, KeySpec::default()));
        for remote in [flood, peer] {
            counters.push(cell(Some(remote), KeySpec { src_addr: true, ..KeySpec::default() }));
        }
    }

    let judge = Judge::new(&config.policy).ok();
    let judged = |c: &Conn| judge.as_ref().and_then(|j| j.result(c, &|v, c| count(&counters, v, c)).ok());
    let mut flows = Vec::new();
    for (i, (inbound, protocol, remote, rport, lport, service, age, bytes)) in shapes.iter().enumerate() {
        let local = IpAddr::V4(here);
        let (src, dst, sport, dport) = if *inbound { (*remote, local, *rport, *lport) } else { (local, *remote, *lport, *rport) };
        let mut flow = Flow {
            id: 0x4000 + i as u32,
            protocol: *protocol,
            direction: Some(if *inbound { Direction::In } else { Direction::Out }),
            loopback: false,
            seen_reply: bytes[1] > 0,
            assured: bytes[1] > 0,
            related: false,
            judged: true,
            ifindex: Some(ifindex),
            timeout_secs: if *protocol == 6 { 431_000 } else { 30 },
            src: Some(src),
            dst: Some(dst),
            src_port: sport,
            dst_port: dport,
            icmp_type: 0,
            icmp_code: 0,
            start_secs: now - age,
            packets: [bytes[0] / 900 + 1, bytes[1] / 900],
            bytes: *bytes,
            slots: [Slot { sentence: None, owner: Some(owner(*service, service.unwrap_or_default(), 300 + i as i32)) }, Slot::default()],
            tags: Vec::new(),
            n_tags: 0,
        };
        let mut c = conn(&flow, config, state);
        c.established = false;
        if let Some(decision) = judged(&c) {
            let verdict = match decision.verdict {
                Verdict::Allow => ntfe::Verdict::Pass,
                Verdict::Reject { prohibited } => ntfe::Verdict::Reject(if prohibited { ntfe::RejectKind::Prohibited } else { ntfe::RejectKind::Refused }),
                _ => ntfe::Verdict::Drop,
            };
            flow.slots[0].sentence = Some(Sentence { generation, expires_at: None, rule_hash: ntfe::rule_hash(decision.by.as_deref().unwrap_or("backstop")), verdict: Some(verdict) });
        }
        flows.push(flow);
    }

    // The verdict stream: new connections over the last fifteen minutes,
    // each judged as the rules judge it now. An SSH flood starts eight
    // minutes ago and eases off.
    let mut events = Vec::new();
    let mut seq = 1_000_000 + minute * 1000;
    let template = |c: &Conn, t: u64| -> Option<Event> {
        let decision = judged(c)?;
        let reports = decision.by.as_deref().and_then(|p| rules::find(config.policy.forest(decision.layer), p)).and_then(rules::Rule::report).is_some();
        Some(Event {
            seq: 0,
            time_ns: t * 1_000_000_000,
            seat: if c.inbound { ntfe::Seat::LocalIn } else { ntfe::Seat::LocalOut },
            layer: Some(match decision.layer {
                rules::Layer::Packet => ntfe::Layer::Packet,
                rules::Layer::RawPacket => ntfe::Layer::RawPacket,
                _ => ntfe::Layer::Flow,
            }),
            verdict: Some(match decision.verdict {
                Verdict::Allow => ntfe::Verdict::Pass,
                Verdict::Reject { prohibited } => ntfe::Verdict::Reject(if prohibited { ntfe::RejectKind::Prohibited } else { ntfe::RejectKind::Refused }),
                _ => ntfe::Verdict::Drop,
            }),
            direction: if c.inbound { Direction::In } else { Direction::Out },
            backstop: decision.by.is_none(),
            fail_closed: false,
            reject_degraded: false,
            rejudged: false,
            identity_unresolved: false,
            protocol: number(&c.protocol),
            flow_state: None,
            ifindex: ifindex as u32,
            src: (if c.inbound { &c.remote } else { &c.local }).parse().ok(),
            dst: (if c.inbound { &c.local } else { &c.remote }).parse().ok(),
            src_port: if c.inbound { c.remote_port } else { c.local_port },
            dst_port: if c.inbound { c.local_port } else { c.remote_port },
            ether_type: 0x0800,
            length: 60,
            effects: ntfe::Effects { reports: u8::from(reports), ..ntfe::Effects::default() },
            attributed: decision.by.unwrap_or_else(|| "backstop".into()),
            local: owner(c.service.as_deref(), c.service.as_deref().unwrap_or_default(), 300),
            remote: Endpoint { kind: EndpointKind::Absent, unresolved: false, pid: 0, guid: [0; 16], comm: String::new(), user: None, service: None },
        })
    };
    let outbound = Conn { inbound: false, remote: "151.101.2.132".into(), remote_port: 443, local: here.to_string(), local_port: 52210, service: Some("peipkg".into()), ..Conn::default() };
    let ssh = |remote: &str| Conn { remote: remote.into(), local: here.to_string(), local_port: 22, service: Some("sshd".into()), ..Conn::default() };
    let stray = Conn { remote: "198.51.100.7".into(), local: here.to_string(), local_port: 3389, ..Conn::default() };
    let samples = [template(&outbound, 0), template(&ssh(&flood.to_string()), 0), template(&stray, 0), template(&ssh(&peer.to_string()), 0)];
    for back in (0..15u64).rev() {
        let start = (minute - back) * 60;
        let flood_now = match back {
            3..=7 => 9 + wobble(start, 6),
            8 | 2 => 1 + wobble(start, 2),
            _ => 0,
        };
        let plan = [(0usize, 38 + wobble(start, 22)), (1, flood_now), (2, 2 + wobble(start + 1, 4)), (3, wobble(start + 2, 2))];
        for (sample, n) in plan {
            let Some(event) = &samples[sample] else { continue };
            for k in 0..n {
                let mut e = event.clone();
                seq += 1;
                e.seq = seq;
                e.time_ns = (start + k * 60 / n.max(1)) * 1_000_000_000;
                events.push(e);
            }
        }
    }
    events.sort_by_key(|e| e.time_ns);

    Live { engine: Engine { generation, pending: false, refusal: None }, listeners, flows, counters, events, example: true }
}

/// The flows' deciding rules, by the hash a sentence names them by: every
/// rule path of every firewall layer.
pub fn rule_by_hash(config: &Config, hash: u64) -> Option<(rules::Layer, String)> {
    rules::Layer::FIREWALL.into_iter().find_map(|layer| rules::walk(config.policy.forest(layer)).into_iter().find(|(p, _, _)| ntfe::rule_hash(p) == hash).map(|(p, _, _)| (layer, p)))
}

/// What the engine decided for `conn` with the counters `live` holds.
pub fn judge(judge: &Judge, live: &Live, conn: &Conn) -> Result<Vec<engine::Decision>, String> {
    judge.conn(conn, &|v, c| count(&live.counters, v, c))
}
