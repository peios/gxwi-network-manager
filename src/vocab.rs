//! PNP's vocabulary, as the editors offer it: every fact a rule can test, in
//! which layers it exists, how it compares and what values it is likely to
//! hold; and every value a profile can set. The reference is the network
//! policy reference in the docs; pnp-core is the judge, and refuses
//! anything this gets wrong before it is written.

/// The layers, as a set: which a fact exists in.
pub const RAW: u8 = 1;
pub const PACKET: u8 = 2;
pub const FLOW: u8 = 4;
pub const IFACE: u8 = 8;
const PKT: u8 = RAW | PACKET | FLOW;

/// How a fact compares, which decides its operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Int,
    Str,
    Addr,
    Mac,
    Flags,
    Sid,
}

/// Where the editor finds suggestions for a fact's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suggest {
    None,
    /// These words.
    Words(&'static [&'static str]),
    /// This machine's interface names.
    Interfaces,
    /// Interface ids.
    InterfaceIds,
    /// Names given to networks.
    NetworkNames,
    /// Network record ids.
    NetworkIds,
    /// Services, by name.
    Services,
    /// Trust levels.
    Trust,
    /// Well-known principals.
    Principals,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fact {
    /// As written in a value name. A name ending in `.` is a prefix the
    /// author completes: `Tag.` and `Counter.`.
    pub name: &'static str,
    pub group: &'static str,
    pub family: Family,
    pub layers: u8,
    pub suggest: Suggest,
    /// What it is, in a few words.
    pub about: &'static str,
}

const fn fact(name: &'static str, group: &'static str, family: Family, layers: u8, suggest: Suggest, about: &'static str) -> Fact {
    Fact { name, group, family, layers, suggest, about }
}

use Family::{Addr, Flags, Int, Mac, Sid, Str};
use Suggest::Words;

pub const PROTOCOLS: &[&str] = &["tcp", "udp", "icmp", "icmpv6", "sctp"];
const INTEGRITY: &[&str] = &["untrusted", "low", "medium", "high", "system"];
pub const TCP_FLAGS: &[&str] = &["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"];
const KINDS: &[&str] = &["wired", "wireless", "loopback", "tunnel", "bridge", "other"];

pub const FACTS: &[Fact] = &[
    fact("Direction", "Connection", Str, PKT, Words(&["in", "out"]), "Incoming or outgoing"),
    fact("Protocol", "Connection", Int, PKT, Words(PROTOCOLS), "The IP protocol"),
    fact("DstPort", "Connection", Int, PKT, Suggest::None, "Port it is sent to"),
    fact("SrcPort", "Connection", Int, PKT, Suggest::None, "Port it is sent from"),
    fact("SrcAddr", "Connection", Addr, PKT, Suggest::None, "Address it is sent from"),
    fact("DstAddr", "Connection", Addr, PKT, Suggest::None, "Address it is sent to"),
    fact("Interface", "Connection", Str, PKT | IFACE, Suggest::Interfaces, "Interface name"),
    fact("Vlan", "Connection", Int, PKT, Suggest::None, "VLAN id"),
    fact("IcmpType", "Connection", Int, PKT, Suggest::None, "ICMP type"),
    fact("IcmpCode", "Connection", Int, PKT, Suggest::None, "ICMP code"),
    fact("Related", "Connection", Int, FLOW, Words(&["0", "1"]), "Expected by another connection"),
    fact("Network.Trust", "Network", Str, PKT | IFACE, Suggest::Trust, "Trust level you gave the network"),
    fact("Network.Name", "Network", Str, PKT | IFACE, Suggest::NetworkNames, "Name you gave the network"),
    fact("Network.Id", "Network", Str, PKT | IFACE, Suggest::NetworkIds, "The network's record"),
    fact("Network.Kind", "Network", Str, IFACE, Words(KINDS), "Kind of interface it was seen on"),
    fact("Local", "Local program", Str, FLOW, Words(&["program", "kernel", "shared", "none"]), "What answers on this machine"),
    fact("Local.Service", "Local program", Sid, FLOW, Suggest::Services, "Service the program runs as"),
    fact("Local.User", "Local program", Sid, FLOW, Suggest::Principals, "User the program runs as"),
    fact("Local.Group", "Local program", Sid, FLOW, Suggest::Principals, "Group the program's user is in"),
    fact("Local.Integrity", "Local program", Int, FLOW, Words(INTEGRITY), "The program's integrity level"),
    fact("Local.Confinement", "Local program", Sid, FLOW, Suggest::None, "The program's confinement"),
    fact("Local.Capability", "Local program", Sid, FLOW, Suggest::None, "A capability of the confinement"),
    fact("Local.Process", "Local program", Str, FLOW, Suggest::None, "The process GUID"),
    fact("Remote", "Local program", Str, FLOW, Words(&["program", "kernel", "shared", "none"]), "The other end, on loopback"),
    fact("Remote.Service", "Local program", Sid, FLOW, Suggest::Services, "Service at the other end, on loopback"),
    fact("Remote.User", "Local program", Sid, FLOW, Suggest::Principals, "User at the other end, on loopback"),
    fact("Remote.Group", "Local program", Sid, FLOW, Suggest::Principals, "Group at the other end, on loopback"),
    fact("Remote.Integrity", "Local program", Int, FLOW, Words(INTEGRITY), "Integrity at the other end"),
    fact("Remote.Confinement", "Local program", Sid, FLOW, Suggest::None, "Confinement at the other end"),
    fact("Remote.Capability", "Local program", Sid, FLOW, Suggest::None, "Capability at the other end"),
    fact("Remote.Process", "Local program", Str, FLOW, Suggest::None, "Process at the other end"),
    fact("EtherType", "Packet", Int, RAW | PACKET, Words(&["ipv4", "ipv6", "arp"]), "Kind of frame"),
    fact("SrcMac", "Packet", Mac, PKT, Suggest::None, "Hardware address it is sent from"),
    fact("DstMac", "Packet", Mac, RAW | PACKET, Suggest::None, "Hardware address it is sent to"),
    fact("Ttl", "Packet", Int, RAW | PACKET, Suggest::None, "Time to live, or hop limit"),
    fact("Dscp", "Packet", Int, RAW | PACKET, Suggest::None, "Differentiated services code"),
    fact("Length", "Packet", Int, RAW | PACKET, Suggest::None, "Packet length in bytes"),
    fact("Fragment", "Packet", Int, RAW | PACKET, Words(&["0", "1"]), "A fragment, before reassembly"),
    fact("TcpFlags", "Packet", Flags, RAW | PACKET, Words(TCP_FLAGS), "TCP flags"),
    fact("FlowState", "Packet", Str, PACKET, Words(&["new", "established", "related", "invalid", "untracked"]), "Connection tracking's view"),
    fact("Time.Hour", "Time (UTC)", Int, PKT, Suggest::None, "Hour now"),
    fact("Time.Minute", "Time (UTC)", Int, PKT, Suggest::None, "Minute now"),
    fact("Time.DayOfWeek", "Time (UTC)", Int, PKT, Suggest::None, "Day now, 1 is Monday"),
    fact("Time.DayOfMonth", "Time (UTC)", Int, PKT, Suggest::None, "Day of the month now"),
    fact("Time.Month", "Time (UTC)", Int, PKT, Suggest::None, "Month now"),
    fact("Time.Year", "Time (UTC)", Int, PKT, Suggest::None, "Year now"),
    fact("Time.Second", "Time (UTC)", Int, PKT, Suggest::None, "Second now"),
    fact("Start.Hour", "Time (UTC)", Int, FLOW, Suggest::None, "Hour the connection began"),
    fact("Start.Minute", "Time (UTC)", Int, FLOW, Suggest::None, "Minute it began"),
    fact("Start.DayOfWeek", "Time (UTC)", Int, FLOW, Suggest::None, "Day it began, 1 is Monday"),
    fact("Start.DayOfMonth", "Time (UTC)", Int, FLOW, Suggest::None, "Day of the month it began"),
    fact("Start.Month", "Time (UTC)", Int, FLOW, Suggest::None, "Month it began"),
    fact("Start.Year", "Time (UTC)", Int, FLOW, Suggest::None, "Year it began"),
    fact("Start.Second", "Time (UTC)", Int, FLOW, Suggest::None, "Second it began"),
    fact("Tag.", "Tags and counters", Int, PACKET | FLOW, Suggest::None, "A tag a rule set on the connection"),
    fact("Counter.", "Tags and counters", Int, PKT, Suggest::None, "A count kept by a rule"),
    fact("Interface.Kind", "Interface", Str, IFACE, Words(KINDS), "Kind of interface"),
    fact("Interface.Id", "Interface", Str, IFACE, Suggest::InterfaceIds, "The interface's stable id"),
    fact("Interface.Mac", "Interface", Mac, IFACE, Suggest::None, "Its hardware address"),
    fact("Interface.Driver", "Interface", Str, IFACE, Suggest::None, "Its driver"),
    fact("Interface.Path", "Interface", Str, IFACE, Suggest::None, "Its place on the bus"),
];

/// The fact a value name's fact part names: an exact name, or a `Tag.` or
/// `Counter.` one.
pub fn lookup(name: &str) -> Option<&'static Fact> {
    FACTS.iter().find(|f| f.name == name).or_else(|| FACTS.iter().find(|f| f.name.ends_with('.') && name.starts_with(f.name) && name.len() > f.name.len()))
}

/// The operators a family takes, as written, in the order offered.
pub fn operators(family: Family) -> &'static [&'static str] {
    match family {
        Int => &["Equal", "GreaterThan", "LessThan", "Present"],
        Flags => &["Has", "Hasnt", "Present"],
        _ => &["Equal", "Present"],
    }
}

/// An operator in words.
pub fn operator_words(op: &str) -> &'static str {
    match op {
        "Equal" => "is",
        "GreaterThan" => "is more than",
        "LessThan" => "is less than",
        "Has" => "has",
        "Hasnt" => "lacks",
        "Present" => "is known",
        _ => "?",
    }
}

/// A profile value's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// On or off.
    Switch,
    /// Yes, no, or follow the default route (absent).
    Tri,
    List,
    Number,
    Choice(&'static [&'static str]),
}

/// One profile value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setting {
    pub bundle: &'static str,
    pub name: &'static str,
    pub shape: Shape,
    pub label: &'static str,
    /// What applies when no profile on the way sets it.
    pub default: &'static str,
    /// An example, for a list or a number.
    pub example: &'static str,
}

impl Setting {
    /// The value's name, `Bundle.Name`.
    pub fn key(&self) -> String {
        format!("{}.{}", self.bundle, self.name)
    }
}

const fn setting(bundle: &'static str, name: &'static str, shape: Shape, label: &'static str, default: &'static str, example: &'static str) -> Setting {
    Setting { bundle, name, shape, label, default, example }
}

/// The bundles, in order, and what each is called.
pub const BUNDLES: &[(&str, &str)] = &[("Address", "Addressing"), ("Route", "Gateway"), ("Dns", "DNS"), ("Hostname", "Hostname"), ("Mtu", "MTU")];

pub const SETTINGS: &[Setting] = &[
    setting("Address", "Offered", Shape::Switch, "Automatic (DHCP, SLAAC)", "Off", ""),
    setting("Address", "Static", Shape::List, "Static addresses", "None", "10.0.0.5/24"),
    setting("Address", "Families", Shape::List, "Families", "IPv4 and IPv6", "ipv4"),
    setting("Address", "LinkLocal", Shape::Switch, "Link-local fallback", "Off", ""),
    setting("Address", "Temporary", Shape::Switch, "IPv6 privacy addresses", "Off", ""),
    setting("Address", "OnExpiry", Shape::Choice(&["Drop", "Keep"]), "On lease expiry", "Drop", ""),
    setting("Route", "Offered", Shape::Switch, "Gateway from the network", "Off", ""),
    setting("Route", "Gateway", Shape::List, "Static gateway", "None", "10.0.0.1"),
    setting("Route", "Metric", Shape::Number, "Metric", "100 wired, 600 wireless", "100"),
    setting("Dns", "Offered", Shape::Switch, "Servers from the network", "Off", ""),
    setting("Dns", "Servers", Shape::List, "Servers", "None", "9.9.9.9"),
    setting("Dns", "Domains", Shape::List, "Domains", "None", "corp.example"),
    setting("Dns", "Default", Shape::Tri, "Default route for names", "Follows the gateway", ""),
    setting("Dns", "Exclusive", Shape::Switch, "Exclusive", "Off", ""),
    setting("Hostname", "Offered", Shape::Switch, "Accept from the network", "Off", ""),
    setting("Hostname", "Announce", Shape::Switch, "Announce", "Off", ""),
    setting("Mtu", "Offered", Shape::Switch, "MTU from the network", "Off", ""),
    setting("Mtu", "Value", Shape::Number, "MTU", "Unchanged", "1500"),
];

pub fn setting_by(key: &str) -> Option<&'static Setting> {
    SETTINGS.iter().find(|s| s.key().eq_ignore_ascii_case(key))
}

/// The trust levels a person picks from. The value is free text: any
/// other is shown as written.
pub const TRUST: &[(&str, &str, &str)] = &[("private", "Private", "A network you control"), ("public", "Public", "Any other network")];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixed_facts_are_found_by_their_prefix() {
        assert_eq!(lookup("Counter.ssh-tries(1m, SrcAddr)").map(|f| f.name), Some("Counter."));
        assert_eq!(lookup("Tag.dnsq").map(|f| f.name), Some("Tag."));
        assert_eq!(lookup("Tag.").map(|f| f.name), Some("Tag."));
        assert_eq!(lookup("DstPort").map(|f| f.family), Some(Family::Int));
        assert!(lookup("Nonsense").is_none());
    }

    #[test]
    fn every_fact_is_one_pnp_core_knows() {
        use pnp_core::FactFamily as F;
        for f in FACTS.iter().filter(|f| !f.name.ends_with('.')) {
            let id = pnp_core::FactId::from_key(f.name).unwrap_or_else(|| panic!("{}", f.name));
            let same = matches!(
                (id.family(), f.family),
                (F::Int, Family::Int) | (F::Str, Family::Str) | (F::Addr, Family::Addr) | (F::Mac, Family::Mac) | (F::Flags, Family::Flags) | (F::Sid, Family::Sid)
            );
            assert!(same, "{} compares as {:?}", f.name, id.family());
            assert_eq!(id.is_at_interface_layer(), f.layers & IFACE != 0, "{} at the interface layer", f.name);
        }
    }

    #[test]
    fn every_setting_is_one_netd_knows() {
        use libnetd::raw::{RawKey, RawValue};
        for s in SETTINGS {
            let value = match s.shape {
                Shape::Switch | Shape::Tri => RawValue::Int(1),
                Shape::Number => RawValue::Int(1500),
                Shape::List => RawValue::List(vec![s.example.into()]),
                Shape::Choice(words) => RawValue::Str(words[0].into()),
            };
            let profile = RawKey { name: "p".into(), values: vec![(s.key(), value)], children: vec![] };
            let root = RawKey { name: "Profiles".into(), values: vec![], children: vec![profile] };
            assert!(libnetd::profile::resolve(&root).is_ok(), "{}", s.key());
        }
    }
}
