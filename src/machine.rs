//! Everything Network Manager shows, read as the person.
//!
//! Two kinds of thing, read at different paces:
//!
//! - **What is configured** ([`Config`]): the registry under
//!   `Machine\System\Network`, which is the truth of the network. Read
//!   whole, and again whenever it changes.
//! - **What is happening** ([`State`]): netd's and resolvd's status, the
//!   kernel's links, addresses and routes (sysfs, procfs), and the
//!   connections to this desktop. netd tells no one when an interface
//!   changes, so this is read every two seconds, each request on a fresh
//!   connection that is closed at once (PEI-1329).

use std::collections::BTreeMap;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use libnetd::{InterfaceStatus, Level};
use libresolv::StatusReport;

use crate::engine::{Conn, Context, Policy, Subject};
use crate::registry::{self, Tree, Value};
use crate::rules::{self, Layer};

pub const NETWORK_KEY: &str = libnetd::NETWORK_KEY;
pub const RESERVATIONS_KEY: &str = "Machine\\System\\Network\\TcpIp\\PortReservations";
const GXWI_KEY: &str = "Machine\\Software\\GXWI";
/// Where the desktop listens when it isn't told otherwise.
const DESKTOP_PORT: u16 = 7780;

/// A network netd has stood on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Network {
    pub id: String,
    pub name: Option<String>,
    /// As written: any text, of which `private` and `public` are offered.
    pub trust: Option<String>,
    pub requested: Option<String>,
    /// What the network showed of itself.
    pub kind: Option<String>,
    pub server: Option<String>,
    pub gateway: Option<String>,
    pub router: Option<String>,
    pub prefixes: Vec<String>,
    pub dns: Vec<String>,
    /// Epoch seconds.
    pub last_seen: Option<i64>,
    pub last_interface: Option<String>,
}

impl Network {
    fn from_tree(tree: &Tree) -> Network {
        let s = |t: &Tree, n: &str| t.value(n).and_then(Value::as_str).map(str::to_string).filter(|v| !v.is_empty());
        let status = tree.child("Status").cloned().unwrap_or_default();
        Network {
            id: tree.name.clone(),
            name: s(tree, "Name"),
            trust: s(tree, "Trust"),
            requested: s(tree, "RequestedAddress"),
            kind: s(&status, "Kind"),
            server: s(&status, "Server"),
            gateway: s(&status, "Gateway"),
            router: s(&status, "Router"),
            prefixes: status.value("Prefixes").and_then(Value::as_list).unwrap_or_default(),
            dns: status.value("DnsServers").and_then(Value::as_list).unwrap_or_default(),
            last_seen: status.value("LastSeen").and_then(Value::as_int),
            last_interface: s(&status, "LastInterface"),
        }
    }

    /// What the person calls it.
    pub fn title(&self) -> String {
        self.name.clone().unwrap_or_else(|| "Unnamed network".into())
    }

    /// Seen and never named or given a trust level.
    pub fn is_new(&self) -> bool {
        self.name.is_none() && self.trust.is_none()
    }

    pub fn context(&self) -> Context {
        Context { id: Some(self.id.clone()), name: self.name.clone(), trust: self.trust.clone(), kind: self.kind.clone() }
    }
}

/// An interface netd has seen, as its inventory records it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inventory {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub mac: String,
    pub path: String,
    pub driver: String,
    pub network: Option<String>,
    pub client_id: Option<String>,
}

/// One port reservation: a selector and the descriptor that says who may
/// bind what it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    /// As written: `tcp:22`, `tcp,udp:1-1023`, or `@` for the default.
    pub selector: String,
    pub sd: Vec<u8>,
}

impl Reservation {
    /// The default reservation is the key's unnamed value, which `reg`
    /// shows as `@`.
    pub fn is_default(&self) -> bool {
        self.selector.is_empty() || self.selector == "@"
    }

    /// The protocols, and the inclusive port range, it covers.
    pub fn covers(&self) -> Option<(Vec<String>, u16, u16)> {
        if self.is_default() {
            return Some((vec!["tcp".into(), "udp".into()], 1, 65535));
        }
        parse_selector(&self.selector)
    }
}

/// Services a per-service SID may be, by name: the authority names
/// accounts, not every service, so a service's SID is matched by deriving
/// it from the name, as peinit does.
const SERVICES: &[&str] = &["sshd", "gxwid", "gxwi-server", "resolvd", "netd", "timed", "pnpd", "atriumd", "authd", "eventd", "loregd", "installerd", "peinit"];

/// What a SID the authority could not name is, when it can be told: a
/// service's own SID, or a capability.
fn known_name(sid: &str) -> Option<String> {
    if sid.starts_with("S-1-5-80-") {
        return SERVICES.iter().find(|s| pnp_core::Sid::service(s).to_string() == sid).map(|s| format!("{s} service"));
    }
    sid.starts_with("S-1-15-3-").then(|| "A capability".to_string())
}

/// A descriptor's access list as (SID, allows, mask), in order: what it
/// grants and denies, and to whom.
pub fn grants(sd: &[u8]) -> Vec<(String, bool, u32)> {
    use peios::security::{AceType, SdView};
    let Ok(view) = SdView::parse(sd) else { return Vec::new() };
    let Some(dacl) = view.dacl() else { return Vec::new() };
    dacl.iter()
        .filter_map(|ace| {
            let allows = match ace.ace_type() {
                AceType::AccessAllowed => true,
                AceType::AccessDenied => false,
                _ => return None,
            };
            Some((ace.sid()?.to_string(), allows, ace.mask()))
        })
        .collect()
}

/// Whether a token with `sids` is granted `right` by `sd`: its access list
/// read in order, a denial before a grant winning, as the kernel reads it.
/// An absent list grants everything; an empty one, nothing.
pub fn granted(sd: &[u8], sids: &[String], right: u32) -> bool {
    use peios::security::SdView;
    if SdView::parse(sd).ok().is_some_and(|v| v.dacl().is_none()) {
        return true;
    }
    for (sid, allows, mask) in grants(sd) {
        if mask & right != 0 && sids.iter().any(|s| *s == sid) {
            return allows;
        }
    }
    false
}

pub fn parse_selector(selector: &str) -> Option<(Vec<String>, u16, u16)> {
    let (protos, ports) = selector.split_once(':')?;
    let protos: Vec<String> = protos.split(',').map(|p| p.trim().to_ascii_lowercase()).collect();
    if protos.is_empty() || protos.iter().any(|p| !matches!(p.as_str(), "tcp" | "udp" | "sctp" | "udplite")) {
        return None;
    }
    let (lo, hi) = match ports.split_once('-') {
        Some((lo, hi)) => (lo.trim().parse().ok()?, hi.trim().parse().ok()?),
        None => {
            let p = ports.trim().parse().ok()?;
            (p, p)
        }
    };
    (lo >= 1 && lo <= hi).then_some((protos, lo, hi))
}

/// The configuration: everything under `Machine\System\Network`.
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub policy: Policy,
    /// The `Rules` key exactly as read: what undoing a change to the rules
    /// writes back, byte for byte.
    pub rules: Option<Tree>,
    pub networks: Vec<Network>,
    pub inventory: Vec<Inventory>,
    /// `CurrentReportingLevel`: 1..6, 6 silencing every report.
    pub reporting: u8,
    pub reservations: Vec<Reservation>,
    pub fallback: Vec<String>,
    pub extra_domains: Vec<String>,
    pub hosts: Vec<(String, String)>,
    pub duid: Option<String>,
    pub hostname: Option<String>,
    /// netd's and resolvd's own descriptors, when set.
    pub netd_security: Option<Vec<u8>>,
    pub resolvd_security: Option<Vec<u8>>,
    pub desktop_port: u16,
    /// What each SID in a descriptor shown is called, by its `S-1-…` text:
    /// asked of the authority while reading, so a render never waits.
    pub names: BTreeMap<String, String>,
    /// Why the registry couldn't be read, if it couldn't.
    pub error: Option<String>,
    /// What the person may change.
    pub may: May,
}

/// What the person may change: what the registry lets them open for
/// writing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct May {
    pub rules: bool,
    pub profiles: bool,
    pub networks: bool,
    pub dns: bool,
    pub reservations: bool,
    pub network_key: bool,
}

impl Config {
    pub fn network(&self, id: &str) -> Option<&Network> {
        self.networks.iter().find(|n| n.id.eq_ignore_ascii_case(id))
    }

    /// The profiles, as a tree.
    pub fn profiles(&self) -> Option<&Tree> {
        self.policy.profiles.as_ref()
    }
}

fn sz(tree: &Tree, name: &str) -> Option<String> {
    tree.value(name).and_then(Value::as_str).map(str::to_string).filter(|s| !s.is_empty())
}

pub fn read_config() -> Config {
    let mut config = Config { reporting: 1, desktop_port: DESKTOP_PORT, ..Config::default() };
    let root = match registry::read(NETWORK_KEY) {
        Ok(Some(root)) => root,
        Ok(None) => Tree::new("Network"),
        Err(e) => {
            config.error = Some(e);
            Tree::new("Network")
        }
    };
    let rules_key = root.child("Rules");
    config.policy = Policy {
        flow: rules::forest(rules_key.and_then(|r| r.child(Layer::Flow.key()))),
        packet: rules::forest(rules_key.and_then(|r| r.child(Layer::Packet.key()))),
        raw: rules::forest(rules_key.and_then(|r| r.child(Layer::RawPacket.key()))),
        interface: rules::forest(rules_key.and_then(|r| r.child(Layer::Interface.key()))),
        profiles: root.child("Profiles").cloned(),
    };
    config.rules = rules_key.cloned();
    config.reporting = rules_key.and_then(|r| r.value("CurrentReportingLevel")).and_then(Value::as_int).map(|l| l.clamp(1, 6) as u8).unwrap_or(1);
    config.networks = root.child("Networks").map(|n| n.children.iter().map(Network::from_tree).collect()).unwrap_or_default();
    config.networks.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.id.cmp(&b.id)));
    config.inventory = root
        .child("Interfaces")
        .map(|i| {
            i.children
                .iter()
                .map(|t| {
                    let status = t.child("Status").cloned().unwrap_or_default();
                    Inventory {
                        id: t.name.clone(),
                        name: sz(&status, "Name").unwrap_or_default(),
                        kind: sz(&status, "Kind").unwrap_or_default(),
                        mac: sz(&status, "Mac").unwrap_or_default(),
                        path: sz(&status, "Path").unwrap_or_default(),
                        driver: sz(&status, "Driver").unwrap_or_default(),
                        network: sz(&status, "Network"),
                        client_id: sz(t, "ClientId"),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    if let Some(ports) = root.at("TcpIp/PortReservations") {
        config.reservations = ports
            .values
            .iter()
            .filter_map(|(name, value)| match value {
                Value::Bytes(sd) => Some(Reservation { selector: name.clone(), sd: sd.clone() }),
                _ => None,
            })
            .collect();
        config.reservations.sort_by_key(|r| (r.is_default(), r.covers().map(|(_, lo, hi)| (hi - lo, lo)).unwrap_or((u16::MAX, 0))));
    }
    if let Some(dns) = root.child("Dns") {
        config.fallback = dns.value("FallbackServers").and_then(Value::as_list).unwrap_or_default();
        config.extra_domains = dns.value("ExtraSearchDomains").and_then(Value::as_list).unwrap_or_default();
        config.hosts = dns.child("Hosts").map(|h| h.values.iter().map(|(n, v)| (n.clone(), v.text())).collect()).unwrap_or_default();
        config.resolvd_security = match dns.value("ControlSecurity") {
            Some(Value::Bytes(b)) if !b.is_empty() => Some(b.clone()),
            _ => None,
        };
    }
    config.duid = sz(&root, "Duid");
    config.hostname = sz(&root, libnetd::hostname::HOSTNAME_VALUE);
    config.netd_security = match root.value("ControlSecurity") {
        Some(Value::Bytes(b)) if !b.is_empty() => Some(b.clone()),
        _ => None,
    };
    config.desktop_port = registry::value(GXWI_KEY, "Listen").and_then(|v| v.as_str().and_then(|s| s.rsplit(':').next()).and_then(|p| p.parse().ok())).unwrap_or(DESKTOP_PORT);
    let mut names = gxwi_sd_editor::names::Names::new();
    let descriptors = config.reservations.iter().map(|r| r.sd.as_slice()).chain(config.netd_security.as_deref()).chain(config.resolvd_security.as_deref());
    for sd in descriptors {
        for (sid, _, _) in grants(sd) {
            if let Ok(parsed) = sid.parse::<peios::security::Sid>() {
                names.learn(&parsed);
                let name = if names.named(&parsed) { names.of(&parsed) } else { known_name(&sid).unwrap_or_else(|| names.of(&parsed)) };
                config.names.insert(sid.clone(), name);
            }
        }
    }
    let may = |path: &str| registry::may_change(path);
    let rules_path = format!("{NETWORK_KEY}\\Rules");
    config.may = May {
        rules: may(&rules_path),
        profiles: may(&format!("{NETWORK_KEY}\\Profiles")),
        networks: may(&format!("{NETWORK_KEY}\\Networks")),
        dns: may(&format!("{NETWORK_KEY}\\Dns")) || (root.child("Dns").is_none() && may(NETWORK_KEY)),
        reservations: may(RESERVATIONS_KEY),
        network_key: may(NETWORK_KEY),
    };
    config
}

/// An address on an interface, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub cidr: String,
    pub source: Source,
    /// Past its preferred lifetime: kept for what uses it, used for
    /// nothing new.
    pub deprecated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Leased by DHCP.
    Leased,
    /// Set in the profile.
    Static,
    /// Made from a router's advertisement, stable.
    Autoconfigured,
    /// A rotating IPv6 privacy address.
    Temporary,
    LinkLocal,
    Other,
}

impl Source {
    pub fn words(self) -> &'static str {
        match self {
            Source::Leased => "DHCP",
            Source::Static => "Static",
            Source::Autoconfigured => "SLAAC, stable",
            Source::Temporary => "Temporary",
            Source::LinkLocal => "Link-local",
            Source::Other => "",
        }
    }
}

/// A route the kernel holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub destination: String,
    pub via: Option<String>,
    pub metric: u32,
}

/// One interface as it is now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Interface {
    pub status: InterfaceStatus,
    pub kind: String,
    pub mtu: Option<u32>,
    /// Mb/s, when the link says.
    pub speed: Option<u32>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub addresses: Vec<Address>,
    pub routes: Vec<Route>,
}

impl Interface {
    pub fn name(&self) -> &str {
        &self.status.name
    }

    pub fn joined(&self) -> bool {
        self.status.verdict.as_deref() == Some("JOIN")
    }

    /// The interface as the interface layer judges it.
    pub fn subject(&self, config: &Config) -> Subject {
        let network = self.status.network.as_deref().and_then(|id| config.network(id)).map(Network::context).or_else(|| {
            self.status.network.as_ref().map(|id| Context { id: Some(id.clone()), name: self.status.network_name.clone(), trust: self.status.network_trust.clone(), kind: None })
        });
        Subject {
            name: self.status.name.clone(),
            kind: self.kind.clone(),
            id: self.status.ifid.clone(),
            mac: self.status.mac.clone(),
            path: self.status.path.clone(),
            driver: self.status.driver.clone(),
            network: network.unwrap_or_default(),
        }
    }
}

/// netd's view of the machine.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Netd {
    pub hostname: String,
    pub level: Level,
    /// Why netd refused the newest interface layer, while the last good one
    /// stands.
    pub refusal: Option<String>,
}

/// What is happening.
#[derive(Debug, Clone)]
pub struct State {
    pub netd: Result<Netd, String>,
    pub interfaces: Vec<Interface>,
    pub resolvd: Result<StatusReport, String>,
    /// Connections to this desktop now: the ones a change mustn't cut.
    pub sessions: Vec<Conn>,
}

impl Default for State {
    fn default() -> State {
        State { netd: Ok(Netd::default()), interfaces: Vec::new(), resolvd: Err("Not read yet.".into()), sessions: Vec::new() }
    }
}

impl State {
    pub fn interface(&self, name: &str) -> Option<&Interface> {
        self.interfaces.iter().find(|i| i.status.name == name)
    }

    /// The interface with the default route, if any.
    pub fn online(&self) -> Option<&Interface> {
        self.interfaces.iter().filter(|i| i.status.level == Level::Routed).max_by_key(|i| i.status.gateway.is_some())
    }
}

const TIMEOUT: Duration = Duration::from_secs(2);

fn netd_status() -> Result<libnetd::Status, String> {
    let mut stream = UnixStream::connect(libnetd::CONTROL_SOCKET_PATH).map_err(|e| format!("netd isn't answering ({e})."))?;
    let _ = stream.set_read_timeout(Some(TIMEOUT));
    let _ = stream.set_write_timeout(Some(TIMEOUT));
    match libnetd::call(&mut stream, &libnetd::Request::Status) {
        Ok(libnetd::Reply::Status(s)) => Ok(s),
        Ok(libnetd::Reply::Error(e)) => Err(e),
        Ok(_) => Err("netd answered something else.".into()),
        Err(e) => Err(format!("netd's answer couldn't be read ({e}).")),
    }
}

/// Asks netd for something: a renewal, a reconcile.
pub fn netd(request: &libnetd::Request) -> Result<(), String> {
    let mut stream = UnixStream::connect(libnetd::CONTROL_SOCKET_PATH).map_err(|e| format!("netd isn't answering ({e})."))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    match libnetd::call(&mut stream, request) {
        Ok(libnetd::Reply::Ok) => Ok(()),
        Ok(libnetd::Reply::Error(e)) if e.contains("denied") || e.contains("access") => Err("netd refused: this needs the Network Control right, which Administrators hold.".into()),
        Ok(libnetd::Reply::Error(e)) => Err(format!("netd refused: {e}")),
        Ok(_) => Err("netd answered something else.".into()),
        Err(e) => Err(format!("netd's answer couldn't be read ({e}).")),
    }
}

/// Asks resolvd something.
pub fn resolvd(request: &libresolv::Request) -> Result<libresolv::Reply, String> {
    let mut stream = UnixStream::connect(libresolv::SOCKET_PATH).map_err(|e| format!("resolvd isn't answering ({e})."))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(8)));
    match libresolv::call(&mut stream, request) {
        Ok(libresolv::Reply::Error(e)) => Err(e),
        Ok(reply) => Ok(reply),
        Err(e) => Err(format!("resolvd's answer couldn't be read ({e}).")),
    }
}

fn sys(name: &str, what: &str) -> Option<String> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/{what}")).ok().map(|s| s.trim().to_string())
}

/// `/proc/net/if_inet6`: each IPv6 address with its flags.
fn inet6() -> Vec<(String, String, u8, u32)> {
    let text = std::fs::read_to_string("/proc/net/if_inet6").unwrap_or_default();
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let [hex, _, prefix, _, flags, name] = f.as_slice() else { return None };
            let bytes: Vec<u8> = (0..16).filter_map(|i| u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()).collect();
            let addr = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes.as_slice()).ok()?);
            Some((name.to_string(), addr.to_string(), u8::from_str_radix(prefix, 16).ok()?, u32::from_str_radix(flags, 16).ok()?))
        })
        .collect()
}

fn routes(name: &str) -> Vec<Route> {
    let mut out = Vec::new();
    let v4 = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    for line in v4.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 || f[0] != name {
            continue;
        }
        let ip = |h: &str| u32::from_str_radix(h, 16).ok().map(|n| std::net::Ipv4Addr::from(n.swap_bytes()));
        let (Some(dest), Some(gw), Some(mask)) = (ip(f[1]), ip(f[2]), ip(f[7])) else { continue };
        let bits = u32::from(mask).count_ones();
        out.push(Route {
            destination: if bits == 0 { "default".into() } else { format!("{dest}/{bits}") },
            via: (!gw.is_unspecified()).then(|| gw.to_string()),
            metric: f[6].parse().unwrap_or(0),
        });
    }
    let v6 = std::fs::read_to_string("/proc/net/ipv6_route").unwrap_or_default();
    for line in v6.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 || f[9] != name {
            continue;
        }
        let ip = |h: &str| -> Option<std::net::Ipv6Addr> {
            let bytes: Vec<u8> = (0..16).filter_map(|i| u8::from_str_radix(h.get(i * 2..i * 2 + 2)?, 16).ok()).collect();
            Some(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes.as_slice()).ok()?))
        };
        let (Some(dest), Ok(bits), Some(gw)) = (ip(f[0]), u8::from_str_radix(f[1], 16), ip(f[4])) else { continue };
        // The local and multicast routes the kernel makes for itself say
        // nothing a person needs.
        if bits == 128 || dest.segments()[0] & 0xff00 == 0xff00 {
            continue;
        }
        out.push(Route {
            destination: if bits == 0 { "default (IPv6)".into() } else { format!("{dest}/{bits}") },
            via: (!gw.is_unspecified()).then(|| gw.to_string()),
            metric: u32::from_str_radix(f[5], 16).unwrap_or(0),
        });
    }
    out
}

/// The desktop's connections now: established TCP to its port, from
/// `/proc/net/tcp` and `tcp6`. Each is a connection a change must not cut.
fn sessions(port: u16, interfaces: &[Interface], config: &Config) -> Vec<Conn> {
    let mut out = Vec::new();
    for (path, v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 || f[3] != "01" {
                continue;
            }
            let parse = |s: &str| -> Option<(String, u16)> {
                let (a, p) = s.split_once(':')?;
                let port = u16::from_str_radix(p, 16).ok()?;
                let addr = if v6 {
                    let words: Vec<u32> = (0..4).filter_map(|i| u32::from_str_radix(a.get(i * 8..i * 8 + 8)?, 16).ok()).collect();
                    let mut bytes = [0u8; 16];
                    for (i, w) in words.iter().enumerate() {
                        bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
                    }
                    let addr = std::net::Ipv6Addr::from(bytes);
                    addr.to_ipv4_mapped().map(|v4| v4.to_string()).unwrap_or_else(|| addr.to_string())
                } else {
                    std::net::Ipv4Addr::from(u32::from_str_radix(a, 16).ok()?.swap_bytes()).to_string()
                };
                Some((addr, port))
            };
            let (Some((local, local_port)), Some((remote, remote_port))) = (parse(f[1]), parse(f[2])) else { continue };
            if local_port != port {
                continue;
            }
            let loopback = remote.starts_with("127.") || remote == "::1";
            let carrier = interfaces.iter().find(|i| i.status.addresses.iter().any(|a| a.split('/').next() == Some(local.as_str())));
            let interface = if loopback { "lo".to_string() } else { carrier.map(|i| i.status.name.clone()).unwrap_or_else(|| "eth0".into()) };
            let network = carrier.map(|i| i.subject(config).network).unwrap_or_default();
            out.push(Conn { inbound: true, protocol: "tcp".into(), remote, remote_port, local, local_port, interface, network, service: Some("gxwid".into()), established: true });
        }
    }
    out
}

/// What makes `addr` the kind of address it is on `status`.
fn source(cidr: &str, status: &InterfaceStatus, statics: &[String], flags: Option<u32>) -> Source {
    let addr = cidr.split('/').next().unwrap_or(cidr);
    if statics.iter().any(|s| s.split('/').next() == Some(addr)) {
        return Source::Static;
    }
    if addr.starts_with("fe80:") || addr.starts_with("169.254.") {
        return Source::LinkLocal;
    }
    if !addr.contains(':') {
        return if status.lease.is_some() { Source::Leased } else { Source::Other };
    }
    match flags {
        // IFA_F_TEMPORARY
        Some(f) if f & 0x01 != 0 => Source::Temporary,
        _ => Source::Autoconfigured,
    }
}

/// The static addresses a profile, with what it inherits, names.
pub fn profile_statics(config: &Config, profile: &str) -> Vec<String> {
    let mut statics = Vec::new();
    let mut here = config.profiles();
    for part in profile.split('/') {
        here = here.and_then(|t| t.child(part));
        if let Some(list) = here.and_then(|t| t.value("Address.Static")).and_then(Value::as_list) {
            statics = list;
        }
    }
    statics
}

pub fn read_state(config: &Config) -> State {
    let mut state = State::default();
    let six = inet6();
    match netd_status() {
        Ok(status) => {
            state.netd = Ok(Netd { hostname: status.hostname.clone(), level: status.level, refusal: status.refusal.clone() });
            for s in status.interfaces {
                if s.name == "lo" {
                    continue;
                }
                let kind = config.inventory.iter().find(|i| i.id == s.ifid).map(|i| i.kind.clone()).unwrap_or_else(|| if sys(&s.name, "wireless").is_some() { "wireless".into() } else { "wired".into() });
                let statics = s.profile.as_deref().map(|p| profile_statics(config, p)).unwrap_or_default();
                let addresses = s
                    .addresses
                    .iter()
                    .map(|cidr| {
                        let addr = cidr.split('/').next().unwrap_or(cidr);
                        let flags = six.iter().find(|(n, a, _, _)| *n == s.name && a == addr).map(|(_, _, _, f)| *f);
                        Address { cidr: cidr.clone(), source: source(cidr, &s, &statics, flags), deprecated: flags.is_some_and(|f| f & 0x20 != 0) }
                    })
                    .collect();
                state.interfaces.push(Interface {
                    kind,
                    mtu: sys(&s.name, "mtu").and_then(|v| v.parse().ok()),
                    speed: sys(&s.name, "speed").and_then(|v| v.parse::<i64>().ok()).filter(|v| *v > 0).map(|v| v as u32),
                    rx_bytes: sys(&s.name, "statistics/rx_bytes").and_then(|v| v.parse().ok()).unwrap_or(0),
                    tx_bytes: sys(&s.name, "statistics/tx_bytes").and_then(|v| v.parse().ok()).unwrap_or(0),
                    addresses,
                    routes: routes(&s.name),
                    status: s,
                });
            }
        }
        Err(e) => {
            state.netd = Err(e);
            // Without netd, the inventory still says what there is.
            for i in &config.inventory {
                let status = InterfaceStatus { ifid: i.id.clone(), name: i.name.clone(), mac: i.mac.clone(), path: i.path.clone(), driver: i.driver.clone(), network: i.network.clone(), ..InterfaceStatus::default() };
                state.interfaces.push(Interface { kind: i.kind.clone(), status, ..Interface::default() });
            }
        }
    }
    state.interfaces.sort_by(|a, b| a.status.name.cmp(&b.status.name));
    state.resolvd = match resolvd(&libresolv::Request::Status) {
        Ok(libresolv::Reply::Status(s)) => Ok(s),
        Ok(_) => Err("resolvd answered something else.".into()),
        Err(e) => Err(e),
    };
    state.sessions = sessions(config.desktop_port, &state.interfaces, config);
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_say_what_they_cover() {
        assert_eq!(parse_selector("tcp:22"), Some((vec!["tcp".into()], 22, 22)));
        assert_eq!(parse_selector("tcp,udp:1-1023"), Some((vec!["tcp".into(), "udp".into()], 1, 1023)));
        assert_eq!(parse_selector("tcp:0"), None);
        assert_eq!(parse_selector("icmp:5"), None);
        assert_eq!(parse_selector("tcp:30-20"), None);
    }

    #[test]
    fn an_address_is_known_by_where_it_came_from() {
        let status = InterfaceStatus { lease: Some(libnetd::LeaseStatus::default()), ..InterfaceStatus::default() };
        assert_eq!(source("10.0.2.15/24", &status, &[], None), Source::Leased);
        assert_eq!(source("10.0.5.20/24", &status, &["10.0.5.20/24".into()], None), Source::Static);
        assert_eq!(source("fe80::1/64", &status, &[], Some(0x80)), Source::LinkLocal);
        assert_eq!(source("2a02::1/64", &status, &[], Some(0x01)), Source::Temporary);
        assert_eq!(source("2a02::2/64", &status, &[], Some(0x00)), Source::Autoconfigured);
    }
}
