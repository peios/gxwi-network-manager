//! Rules judged by the machine's own engine.
//!
//! Every change to the rules is checked here before it is written, with the
//! laws the kernel and netd apply when they read it: pnp-core's ingestion
//! for each packet layer and across them, the limits NTFE adds on top
//! (depth, count, value types), and netd's own build of the interface
//! layer and the profiles (libnetd's `policy`), including the tie between
//! two profiles that netd refuses. A change the machine would refuse is
//! refused here, with the reason, and never reaches the registry.
//!
//! Every "why" is answered here too: a connection described by the person,
//! or one the live state reports, is judged by pnp-core against the rules,
//! layer by layer in the order the kernel judges them, and each rule's part
//! in the decision is traced.

use std::net::IpAddr;

use libnetd::raw::{RawKey, RawValue};
use pnp_core::{
    CondKey, CondOp, Direction, EndpointKind, EvalContext, FactId, OwnedPrincipal, RegValue, RuleInput, Sid, Snapshot, TimeFacts,
};

use crate::registry::{Tree, Value};
use crate::rules::{self, Cond, Forest, Layer, Rule, Verdict};

/// NTFE's walk bounds, on top of pnp-core's (`ntfe/ntfe.h`): a root rule is
/// at depth 0, and a rule deeper than this refuses the generation.
pub const MAX_DEPTH: usize = 12;
pub const MAX_RULES: usize = 4096;

/// The rules and profiles of one generation, as they stand or as a change
/// would leave them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    pub flow: Forest,
    pub packet: Forest,
    pub raw: Forest,
    pub interface: Forest,
    /// The `Profiles` key.
    pub profiles: Option<Tree>,
}

impl Policy {
    pub fn forest(&self, layer: Layer) -> &Forest {
        match layer {
            Layer::Flow => &self.flow,
            Layer::Packet => &self.packet,
            Layer::RawPacket => &self.raw,
            Layer::Interface => &self.interface,
        }
    }

    pub fn forest_mut(&mut self, layer: Layer) -> &mut Forest {
        match layer {
            Layer::Flow => &mut self.flow,
            Layer::Packet => &mut self.packet,
            Layer::RawPacket => &mut self.raw,
            Layer::Interface => &mut self.interface,
        }
    }
}

/// What an interface is, as the interface layer judges it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Subject {
    pub name: String,
    pub kind: String,
    pub id: String,
    pub mac: String,
    pub path: String,
    pub driver: String,
    pub network: Context,
}

/// The network an interface stands on, as the rules see it: each fact
/// absent until netd identified a network and the person named it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Context {
    pub id: Option<String>,
    pub name: Option<String>,
    pub trust: Option<String>,
    /// The kind of interface it was seen on (the interface layer only).
    pub kind: Option<String>,
}

/// What a check found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Why the machine would refuse the generation: nothing is written
    /// while there is one.
    pub refusals: Vec<String>,
    /// Rules that are legal but can never match as written.
    pub lints: Vec<String>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.refusals.is_empty()
    }
}

fn reg_value(value: &Value) -> Option<RegValue> {
    Some(match value {
        Value::Int(i) => RegValue::Int(*i),
        Value::Str(s) => RegValue::Str(s.as_str().into()),
        Value::List(items) => RegValue::List(items.iter().map(|s| RegValue::Str(s.as_str().into())).collect::<Vec<_>>().into()),
        Value::Bytes(_) => return None,
    })
}

fn input(rule: &Rule, path: &str) -> Result<RuleInput, String> {
    let mut out = RuleInput { name: rule.name.as_str().into(), values: Vec::new().into(), children: Vec::new().into() };
    for (name, value) in rule.values() {
        let value = reg_value(&value).ok_or_else(|| format!("Rule {path}: {name} holds bytes, which no rule value may."))?;
        out.values.push((name.as_str().into(), value)).map_err(|_| "Out of memory.".to_string())?;
    }
    for child in &rule.children {
        let child = input(child, &format!("{path}/{}", child.name))?;
        out.children.push(child).map_err(|_| "Out of memory.".to_string())?;
    }
    Ok(out)
}

fn inputs(forest: &[Rule]) -> Result<Vec<RuleInput>, String> {
    forest.iter().map(|r| input(r, &r.name)).collect()
}

/// A built forest, or why the machine would refuse it.
pub fn build(layer: Layer, forest: &[Rule]) -> Result<pnp_core::BuildOutput, String> {
    if rules::count(forest) > MAX_RULES {
        return Err(format!("{} has more than {MAX_RULES} rules.", layer.title()));
    }
    if let Some((path, _, _)) = rules::walk(forest).into_iter().find(|(_, d, _)| *d > MAX_DEPTH) {
        return Err(format!("Rule {path} is nested more than {MAX_DEPTH} deep."));
    }
    pnp_core::build_forest(layer.core(), &inputs(forest)?).map_err(|e| describe(&e))
}

/// Why pnp-core refused, in words.
pub fn describe(e: &pnp_core::BuildError) -> String {
    use pnp_core::{ActionParseError as A, BuildError as B};
    match e {
        B::Alloc => "Out of memory.".into(),
        B::UnknownFact { rule, key } => format!("Rule {}: {} tests nothing PNP knows.", rule.as_str(), key.as_str()),
        B::BadOperator { rule, key } => format!("Rule {}: {} can't be compared that way.", rule.as_str(), key.as_str()),
        B::BadPattern { rule, key } => format!("Rule {}: the value of {} isn't one it can hold.", rule.as_str(), key.as_str()),
        B::BadCounterView { rule, key } => format!("Rule {}: {} isn't a count PNP can keep: a name, then at most one window up to 1d and one key.", rule.as_str(), key.as_str()),
        B::BadActionsValue { rule } => format!("Rule {}: its actions aren't a list.", rule.as_str()),
        B::BadAction { rule, detail } => format!(
            "Rule {}: {}",
            rule.as_str(),
            match detail {
                A::UnknownAction => "an action PNP doesn't have.",
                A::BadArity => "an action with the wrong number of arguments.",
                A::BadArgument => "an action with an argument it can't take.",
                A::UnknownRejectKind => "a reject with a reply PNP doesn't have.",
                A::Malformed => "an action that isn't written properly.",
            }
        ),
        B::PromptChainTooDeep { rule } => format!("Rule {}: prompts nest too deep.", rule.as_str()),
        B::BadPriority { rule } => format!("Rule {}: its priority isn't a whole number.", rule.as_str()),
        B::BadEnabled { rule } => format!("Rule {}: Enabled isn't 0 or 1.", rule.as_str()),
        B::BadRuleName { rule } => format!("Rule {}: a name can't be empty or contain / or \\.", rule.as_str()),
        B::TagHashCollision { a, b } => format!("The tags {} and {} can't both be used: rename one.", a.as_str(), b.as_str()),
        B::StreamHashCollision { a, b } => format!("The counts {} and {} can't both be used: rename one.", a.as_str(), b.as_str()),
        B::CounterNeverWritten { rule, key } => {
            let name = key.as_str().trim_start_matches("Counter.").split(['(', '.']).next().unwrap_or_default().to_string();
            format!("Rule {}: no rule counts into “{name}”. Add a Count action to the rule that should.", rule.as_str())
        }
        B::TagDownwardRead { rule, name } => format!("Rule {}: tag {} is set in a later layer, so it can't be read here.", rule.as_str(), name.as_str()),
        B::PresentNeverAtLayer { rule, key } => format!("Rule {}: {} never exists in this layer, so “is known” can't be asked of it.", rule.as_str(), key.as_str()),
        B::KeyNotAtLayer { rule, key } => format!("Rule {}: {} doesn't exist in profile rules.", rule.as_str(), key.as_str()),
        B::ActionNotAtLayer { rule } => format!("Rule {}: an action this layer can't take.", rule.as_str()),
    }
}

/// A key in the neutral shape netd's laws read.
pub fn raw(tree: &Tree) -> RawKey {
    RawKey {
        name: tree.name.clone(),
        values: tree
            .values
            .iter()
            .map(|(n, v)| {
                let v = match v {
                    Value::Int(i) => RawValue::Int(*i),
                    Value::Str(s) => RawValue::Str(s.clone()),
                    Value::List(items) => RawValue::List(items.clone()),
                    Value::Bytes(_) => RawValue::Other,
                };
                (n.clone(), v)
            })
            .collect(),
        children: tree.children.iter().map(raw).collect(),
    }
}

/// The interface layer and profiles, as netd builds them.
pub fn interface_policy(policy: &Policy) -> Result<libnetd::policy::Policy, String> {
    let mut layer = Tree::new("Interface");
    layer.children = policy.interface.iter().map(Rule::tree).collect();
    let rules = (!policy.interface.is_empty()).then(|| raw(&layer));
    let profiles = policy.profiles.as_ref().map(raw);
    libnetd::policy::build(rules.as_ref(), profiles.as_ref()).map_err(netd_words)
}

/// netd's reasons are terse; the person reads them as a sentence.
fn netd_words(why: String) -> String {
    let mut words = why;
    if let Some(first) = words.get(..1) {
        words = first.to_uppercase() + &words[1..];
    }
    if !words.ends_with('.') {
        words.push('.');
    }
    words
}

/// Checks the generation `policy` would make: whether the kernel and
/// netd would take it, and what in it can never match. `subjects` are the
/// machine's interfaces, judged for a tie netd refuses.
pub fn check(policy: &Policy, subjects: &[Subject]) -> Report {
    let mut report = Report::default();
    let mut built = Vec::new();
    for layer in [Layer::RawPacket, Layer::Packet, Layer::Flow] {
        match build(layer, policy.forest(layer)) {
            Ok(out) => {
                for lint in out.lints.iter() {
                    report.lints.push(format!("Rule {}: {} never exists in {}, so it can never match.", lint.rule.as_str(), lint.key.as_str(), layer.title().to_lowercase()));
                }
                built.push(out.forest);
            }
            Err(why) => report.refusals.push(why),
        }
    }
    if built.len() == 3 {
        let forests: Vec<&pnp_core::Forest> = built.iter().collect();
        if let Err(e) = pnp_core::check_forests(&forests) {
            report.refusals.push(describe(&e));
        }
    }
    if let Some((path, _, _)) = rules::walk(&policy.interface).into_iter().find(|(_, d, _)| *d > MAX_DEPTH) {
        report.refusals.push(format!("Rule {path} is nested more than {MAX_DEPTH} deep."));
    }
    match interface_policy(policy) {
        Ok(netd) => {
            report.lints.extend(netd.lints.iter().map(|l| netd_words(l.clone())));
            for subject in subjects {
                let judged = netd.judge(&interface_snapshot(subject));
                if judged.conflict {
                    report.refusals.push(format!("On {}, rules {} have the same priority and choose different profiles. Give one a higher priority.", subject.name, judged.rule.replace(" vs ", " and ")));
                }
            }
        }
        Err(why) => report.refusals.push(why),
    }
    report
}

fn pkm(s: &str) -> pnp_core::pkm_alloc::String {
    s.into()
}

fn mac(text: &str) -> Option<[u8; 6]> {
    let parts: Vec<u8> = text.split(':').filter_map(|p| u8::from_str_radix(p, 16).ok()).collect();
    <[u8; 6]>::try_from(parts.as_slice()).ok()
}

/// An interface as the interface layer sees it.
pub fn interface_snapshot(subject: &Subject) -> Snapshot<'static> {
    let opt = |s: &str| (!s.is_empty()).then(|| pkm(s));
    Snapshot {
        interface: Some(pkm(&subject.name)),
        interface_kind: opt(&subject.kind),
        interface_id: opt(&subject.id),
        interface_mac: mac(&subject.mac),
        interface_path: opt(&subject.path),
        interface_driver: opt(&subject.driver),
        network_id: subject.network.id.as_deref().map(pkm),
        network_name: subject.network.name.as_deref().map(pkm),
        network_trust: subject.network.trust.as_deref().map(pkm),
        network_kind: subject.network.kind.as_deref().map(pkm),
        ..Snapshot::default()
    }
}

/// How the interface layer judges `subject`: the verdict, the rule that
/// spoke (`None` for the backstop), and whether rules tied.
pub fn judge_interface(netd: &libnetd::policy::Policy, subject: &Subject) -> (Verdict, Option<String>, bool) {
    use libnetd::policy::Outcome;
    let judged = netd.judge(&interface_snapshot(subject));
    let verdict = match &judged.outcome {
        Outcome::Join(p) => Verdict::Join(p.path.clone()),
        Outcome::Down => Verdict::Down,
        Outcome::Ignore => Verdict::Ignore,
    };
    (verdict, (!judged.backstop).then_some(judged.rule), judged.conflict)
}

/// A connection, as the firewall judges it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conn {
    pub inbound: bool,
    pub protocol: String,
    /// The other machine's address.
    pub remote: String,
    pub remote_port: u16,
    /// This machine's address.
    pub local: String,
    pub local_port: u16,
    /// The interface it crosses; `lo` for one within this machine.
    pub interface: String,
    pub network: Context,
    /// The service at this machine's end, if a service is there. For an
    /// incoming connection with none, nothing listens.
    pub service: Option<String>,
    /// Whether the connection is already established: the packet layer
    /// sees its packets as such.
    pub established: bool,
}

impl Default for Conn {
    fn default() -> Conn {
        Conn {
            inbound: true,
            protocol: "tcp".into(),
            remote: "198.51.100.7".into(),
            remote_port: 51544,
            local: "192.0.2.10".into(),
            local_port: 22,
            interface: "eth0".into(),
            network: Context::default(),
            service: None,
            established: false,
        }
    }
}

impl Conn {
    /// The port on this machine for an incoming connection, else the
    /// other machine's.
    pub fn port(&self) -> u16 {
        if self.inbound { self.local_port } else { self.remote_port }
    }
}

fn protocol_number(p: &str) -> Option<u8> {
    match p.to_ascii_lowercase().as_str() {
        "tcp" => Some(6),
        "udp" => Some(17),
        "icmp" => Some(1),
        "icmpv6" => Some(58),
        "sctp" => Some(132),
        other => other.parse().ok(),
    }
}

/// The clock now, as rules read it (UTC).
fn now() -> (i64, TimeFacts) {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    (secs, civil(secs))
}

/// Epoch seconds as a UTC calendar date and time (Howard Hinnant's days
/// from civil, inverted).
pub fn civil(secs: i64) -> TimeFacts {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    // 1970-01-01 was a Thursday, ISO 4.
    let day_of_week = (days + 3).rem_euclid(7) + 1;
    TimeFacts { year, month, day_of_month: day, day_of_week, hour: rem / 3600, minute: rem % 3600 / 60, second: rem % 60 }
}

/// The principal a service runs as: its service SID among its groups, as
/// peinit mints its token.
fn service_principal(name: &str) -> OwnedPrincipal {
    let mut principal = OwnedPrincipal { user: Sid::well_known("LocalService").unwrap_or_default(), integrity: 16384, ..OwnedPrincipal::default() };
    for sid in [Some(Sid::service(name)), Sid::well_known("Everyone"), Sid::well_known("Service"), Sid::well_known("AuthenticatedUsers")].into_iter().flatten() {
        let _ = principal.groups.push(sid);
    }
    principal
}

/// A connection's first packet as `layer` sees it. Counters come from
/// `counts`, by the view the forest reads.
fn conn_snapshot<'a>(conn: &Conn, layer: Layer, forest: &pnp_core::Forest, local: Option<&'a OwnedPrincipal>, counts: &dyn Fn(&pnp_core::CounterView, &Conn) -> Option<u64>) -> Snapshot<'a> {
    let remote: Option<IpAddr> = conn.remote.parse().ok();
    let here: Option<IpAddr> = if conn.interface == "lo" { remote } else { conn.local.parse().ok() };
    let (src, dst, sport, dport) = if conn.inbound { (remote, here, conn.remote_port, conn.local_port) } else { (here, remote, conn.local_port, conn.remote_port) };
    let protocol = protocol_number(&conn.protocol);
    let ported = matches!(protocol, Some(6 | 17 | 132));
    let (secs, time) = now();
    let mut snap = Snapshot {
        direction: Some(if conn.inbound { Direction::In } else { Direction::Out }),
        interface: Some(pkm(&conn.interface)),
        src_addr: src,
        dst_addr: dst,
        protocol,
        src_port: ported.then_some(sport),
        dst_port: ported.then_some(dport),
        time: Some(time),
        now_secs: Some(secs),
        network_id: conn.network.id.as_deref().map(pkm),
        network_name: conn.network.name.as_deref().map(pkm),
        network_trust: conn.network.trust.as_deref().map(pkm),
        ..Snapshot::default()
    };
    if conn.interface == "lo" {
        snap.network_id = None;
        snap.network_name = None;
        snap.network_trust = None;
    }
    if matches!(protocol, Some(1 | 58)) {
        snap.icmp_type = Some(if protocol == Some(1) { 8 } else { 128 });
        snap.icmp_code = Some(0);
    }
    match layer {
        Layer::Flow => {
            snap.related = Some(false);
            snap.start = Some(time);
            snap.local = Some(match local {
                Some(p) => pnp_core::Endpoint { kind: EndpointKind::Program, principal: Some(p) },
                None => pnp_core::Endpoint { kind: if conn.inbound { EndpointKind::None } else { EndpointKind::Kernel }, principal: None },
            });
        }
        Layer::Packet | Layer::RawPacket => {
            snap.ether_type = Some(if matches!(src, Some(IpAddr::V6(_))) { 0x86dd } else { 0x0800 });
            snap.ttl = Some(64);
            snap.dscp = Some(0);
            snap.length = Some(60);
            if protocol == Some(6) {
                snap.tcp_flags = Some(if conn.established { pnp_core::tcp_flags::ACK } else { pnp_core::tcp_flags::SYN });
            }
            if layer == Layer::Packet {
                snap.flow_state = Some(if conn.established { pnp_core::FlowState::Established } else { pnp_core::FlowState::New });
            } else {
                snap.fragment = Some(false);
            }
        }
        Layer::Interface => {}
    }
    for (i, view) in forest.views.iter().enumerate() {
        if let Some(n) = counts(view, conn) {
            let _ = snap.counter_views.push((i as u32, n));
        }
    }
    snap
}

/// One rule's part in a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    /// It matched, and its verdict decided.
    Decides,
    /// It matched and spoke, but another rule outranked it.
    Outranked,
    /// It matched and said the same as the rule that decided, at the same
    /// priority: either could have been named.
    Agrees,
    /// It matched, but an exception inside it matched too and speaks
    /// for the connection.
    Shadowed,
    /// It matched with no verdict of its own; the rule it is inside, named,
    /// speaks for it.
    Inherits(String),
    /// It matched with no verdict, and nothing it is inside has one: only
    /// its other actions run.
    Effects,
    NoMatch,
    Off,
}

/// One rule in a trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub path: String,
    pub depth: usize,
    pub part: Part,
    /// Each condition, and whether it held (`None` when the engine has no
    /// such condition, as for one it refused).
    pub conds: Vec<(Cond, Option<bool>)>,
    pub priority: i64,
    pub verdict: Option<Verdict>,
    pub effects: Vec<String>,
}

/// One layer's decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub layer: Layer,
    pub verdict: Verdict,
    /// The rule that decided, or `None` for the layer's default.
    pub by: Option<String>,
    pub priority: i64,
    /// How many rules spoke.
    pub speakers: usize,
    /// More than one spoke at the winning priority, and the stricter won.
    pub tie: bool,
    /// How many spoke at the winning priority with the winning verdict.
    pub agreeing: usize,
    pub steps: Vec<Step>,
}

impl Decision {
    pub fn passes(&self) -> bool {
        self.verdict == Verdict::Allow
    }
}

fn verdict(v: pnp_core::Verdict, forest: &pnp_core::Forest) -> Verdict {
    use pnp_core::{RejectKind, Verdict as V};
    match v {
        V::Pass => Verdict::Allow,
        V::Drop => Verdict::Block,
        V::Reject(k) => Verdict::Reject { prohibited: k == RejectKind::Prohibited },
        V::Join(i) => Verdict::Join(forest.profiles.get(i as usize).map(|p| p.as_str().to_string()).unwrap_or_default()),
        V::Ignore => Verdict::Ignore,
        V::Down => Verdict::Down,
    }
}

/// Whether condition `cond` of a rule held, found among the built rule's
/// conditions by what it tests and how.
fn held(cond: &Cond, built: &pnp_core::Rule, forest: &pnp_core::Forest, snap: &Snapshot<'_>) -> Option<bool> {
    let same_op = |op: &CondOp| match cond.op.as_str() {
        "Equal" => matches!(op, CondOp::EqualInt(_) | CondOp::EqualStr(_) | CondOp::EqualAddr(_) | CondOp::EqualMac(_) | CondOp::EqualSid(_)),
        "GreaterThan" => matches!(op, CondOp::Gt(_)),
        "LessThan" => matches!(op, CondOp::Lt(_)),
        "Has" => matches!(op, CondOp::Has(_)),
        "Hasnt" => matches!(op, CondOp::Hasnt(_)),
        "Present" => matches!(op, CondOp::Present(_)),
        _ => false,
    };
    let fact = FactId::from_key(&cond.fact);
    let view = cond.fact.strip_prefix("Counter.").and_then(|spec| pnp_core::CounterView::parse(spec).ok());
    let tag = cond.fact.strip_prefix("Tag.");
    built
        .conditions
        .iter()
        .find(|c| {
            same_op(&c.op)
                && match (&c.key, fact, &view, tag) {
                    (CondKey::Fact(f), Some(want), _, _) => *f == want,
                    (CondKey::Counter(i), _, Some(want), _) => forest.views.get(*i as usize) == Some(want),
                    (CondKey::Tag { name, .. }, _, _, Some(want)) => name.as_str() == want,
                    _ => false,
                }
        })
        .map(|c| c.matches(snap))
}

/// Traces one forest's rules against a snapshot, given the evaluation.
fn trace(mine: &[Rule], built: &pnp_core::Forest, snap: &Snapshot<'_>, winner: &str, top: Option<(pnp_core::Verdict, i64)>) -> Vec<Step> {
    struct Walk<'s, 'a> {
        forest: &'s pnp_core::Forest,
        snap: &'s Snapshot<'a>,
        winner: &'s str,
        /// The deciding verdict and its priority.
        top: Option<(pnp_core::Verdict, i64)>,
        out: Vec<Step>,
    }
    impl Walk<'_, '_> {
        /// Returns whether the rule matched. `voices` are the ancestors
        /// with a verdict, nearest last.
        fn rule(&mut self, mine: &Rule, built: &pnp_core::Rule, path: String, depth: usize, voices: &[String]) -> bool {
            let conds: Vec<(Cond, Option<bool>)> = mine.conds.iter().map(|c| (c.clone(), held(c, built, self.forest, self.snap))).collect();
            let at = self.out.len();
            self.out.push(Step {
                path: path.clone(),
                depth,
                part: Part::NoMatch,
                conds,
                priority: built.priority,
                verdict: mine.verdict().and_then(rules::verdict_of),
                effects: mine.effects().into_iter().map(String::from).collect(),
            });
            if !built.enabled {
                self.out[at].part = Part::Off;
                return false;
            }
            if !built.matches(self.snap) {
                return false;
            }
            let mut voices = voices.to_vec();
            if built.has_direct_verdict() {
                voices.push(path.clone());
            }
            let mut any = false;
            for child in built.children.iter() {
                let name = child.name.as_str();
                let Some(own) = mine.children.iter().find(|r| r.name == name) else { continue };
                any |= self.rule(own, child, format!("{path}/{name}"), depth + 1, &voices);
            }
            self.out[at].part = if any {
                Part::Shadowed
            } else if built.has_direct_verdict() {
                if path == self.winner {
                    Part::Decides
                } else if built.direct_verdict().zip(Some(built.priority)) == self.top {
                    Part::Agrees
                } else {
                    Part::Outranked
                }
            } else {
                match voices.last() {
                    Some(up) => Part::Inherits(up.clone()),
                    None => Part::Effects,
                }
            };
            true
        }
    }
    let mut walk = Walk { forest: built, snap, winner, top, out: Vec::new() };
    for root in built.roots.iter() {
        if let Some(own) = mine.iter().find(|r| r.name == root.name.as_str()) {
            walk.rule(own, root, own.name.clone(), 0, &[]);
        }
    }
    walk.out
}

/// What a forest decides for a snapshot, traced.
fn decide(layer: Layer, mine: &[Rule], built: &pnp_core::Forest, snap: &Snapshot<'_>) -> Result<Decision, String> {
    let e = pnp_core::evaluate(built, snap, &EvalContext::default()).map_err(|_| "Out of memory.".to_string())?;
    let winner = e.attributed_to.as_str().to_string();
    let top = e.candidates.iter().map(|c| c.priority).max().unwrap_or(0);
    let at_top: Vec<&pnp_core::VerdictCandidate> = e.candidates.iter().filter(|c| c.priority == top).collect();
    let steps = trace(mine, built, snap, &winner, (!e.backstop).then_some((e.verdict, top)));
    // An abstaining rule's ancestor is attributed the decision: it is the
    // rule that decided, though it reached it through its exception.
    Ok(Decision {
        layer,
        verdict: verdict(e.verdict, built),
        by: (!e.backstop).then_some(winner),
        priority: if e.backstop { 0 } else { top },
        speakers: e.candidates.len(),
        tie: at_top.iter().any(|c| c.verdict != e.verdict),
        agreeing: at_top.iter().filter(|c| c.verdict == e.verdict).count(),
        steps,
    })
}

/// Rules built for judging connections: each firewall layer once.
pub struct Judge {
    policy: Policy,
    built: Vec<(Layer, pnp_core::Forest)>,
}

impl Judge {
    /// Builds the firewall layers of `policy`, or says why one can't be.
    pub fn new(policy: &Policy) -> Result<Judge, String> {
        let mut built = Vec::new();
        for layer in Layer::FIREWALL {
            built.push((layer, build(layer, policy.forest(layer))?.forest));
        }
        Ok(Judge { policy: policy.clone(), built })
    }

    fn built(&self, layer: Layer) -> &pnp_core::Forest {
        &self.built.iter().find(|(l, _)| *l == layer).expect("every firewall layer is built").1
    }

    /// One layer's decision for `conn`.
    pub fn layer(&self, layer: Layer, conn: &Conn, counts: &dyn Fn(&pnp_core::CounterView, &Conn) -> Option<u64>) -> Result<Decision, String> {
        let principal = conn.service.as_deref().map(service_principal);
        let built = self.built(layer);
        let snap = conn_snapshot(conn, layer, built, principal.as_ref(), counts);
        decide(layer, self.policy.forest(layer), built, &snap)
    }

    /// Every layer's decision for `conn`, in the order the kernel judges
    /// it, as far as the first that refuses it.
    pub fn conn(&self, conn: &Conn, counts: &dyn Fn(&pnp_core::CounterView, &Conn) -> Option<u64>) -> Result<Vec<Decision>, String> {
        let order = if conn.inbound { [Layer::RawPacket, Layer::Packet, Layer::Flow] } else { [Layer::Flow, Layer::Packet, Layer::RawPacket] };
        let mut out = Vec::new();
        for layer in order {
            let decision = self.layer(layer, conn, counts)?;
            let passes = decision.passes();
            out.push(decision);
            if !passes {
                break;
            }
        }
        Ok(out)
    }

    /// The decision that stands for `conn`: the first refusal, else the
    /// last layer's.
    pub fn result(&self, conn: &Conn, counts: &dyn Fn(&pnp_core::CounterView, &Conn) -> Option<u64>) -> Result<Decision, String> {
        self.conn(conn, counts).map(|mut d| d.pop().expect("at least one layer"))
    }
}

/// No counts at all: what a check that only asks "allowed?" uses.
pub fn no_counts(_: &pnp_core::CounterView, _: &Conn) -> Option<u64> {
    None
}

#[cfg(test)]
pub mod tests {
    use super::*;

    fn rule(name: &str, conds: &[(&str, &str, &[&str])], actions: &[&str]) -> Rule {
        let mut r = Rule::new(name);
        r.conds = conds.iter().map(|(f, o, v)| Cond::new(f, o, v)).collect();
        r.actions = actions.iter().map(|s| s.to_string()).collect();
        r
    }

    /// The shipped seed (pkm/regim/pnp-rules.reg, sshd's and gxwi's), with
    /// an SSH rate limit as an exception.
    pub fn seed() -> Policy {
        let mut ssh = rule("ssh", &[("Direction", "Equal", &["in"]), ("Protocol", "Equal", &["tcp"]), ("DstPort", "Equal", &["22"])], &["PASS"]);
        ssh.children.push(rule("too-fast", &[("Counter.ssh-tries(1m, SrcAddr)", "GreaterThan", &["10"])], &["REJECT(Prohibited)", "REPORT(3)"]));
        let mut wired = rule("wired", &[("Interface.Kind", "Equal", &["wired"])], &["JOIN(default)"]);
        wired.priority = Some(10);
        let mut profiles = Tree::new("Profiles");
        let mut default = Tree::new("default");
        default.values = vec![("Address.Offered".into(), Value::Int(1)), ("Route.Offered".into(), Value::Int(1)), ("Dns.Offered".into(), Value::Int(1))];
        default.children.push(Tree { name: "home".into(), values: vec![("Address.Temporary".into(), Value::Int(1))], children: vec![] });
        profiles.children.push(default);
        Policy {
            flow: vec![
                rule("outbound-ok", &[("Direction", "Equal", &["out"])], &["PASS"]),
                rule("loopback", &[("Interface", "Equal", &["lo"])], &["PASS"]),
                rule("gxwi-experimental", &[("Direction", "Equal", &["in"]), ("Protocol", "Equal", &["tcp"]), ("DstPort", "Equal", &["7780"])], &["PASS"]),
                ssh,
                rule("ssh-watch", &[("Direction", "Equal", &["in"]), ("Protocol", "Equal", &["tcp"]), ("DstPort", "Equal", &["22"])], &["COUNT(ssh-tries)"]),
            ],
            packet: vec![
                rule("tracked", &[("FlowState", "Equal", &["new", "established", "related"])], &["PASS"]),
                rule("outbound-ok", &[("Direction", "Equal", &["out"])], &["PASS"]),
                rule("loopback", &[("Interface", "Equal", &["lo"])], &["PASS"]),
            ],
            raw: vec![rule("all", &[], &["PASS"])],
            interface: vec![wired],
            profiles: Some(profiles),
        }
    }

    fn eth0() -> Subject {
        Subject { name: "eth0".into(), kind: "wired".into(), id: "if-1".into(), mac: "52:54:00:12:34:56".into(), path: "pci-0000:00:03.0".into(), driver: "virtio_net".into(), network: Context::default() }
    }

    fn ssh_from(remote: &str) -> Conn {
        Conn { remote: remote.into(), local_port: 22, service: Some("sshd".into()), ..Conn::default() }
    }

    fn flood(view: &pnp_core::CounterView, conn: &Conn) -> Option<u64> {
        (view.name.as_str() == "ssh-tries" && conn.remote == "203.0.113.50").then_some(14)
    }

    #[test]
    fn the_seed_is_one_the_machine_takes() {
        let report = check(&seed(), &[eth0()]);
        assert!(report.ok(), "{:?}", report.refusals);
    }

    #[test]
    fn ssh_is_allowed_until_a_source_tries_too_often() {
        let judge = Judge::new(&seed()).unwrap();
        let calm = judge.result(&ssh_from("192.168.1.31"), &flood).unwrap();
        assert_eq!((calm.verdict, calm.by.as_deref()), (Verdict::Allow, Some("ssh")));
        let busy = judge.result(&ssh_from("203.0.113.50"), &flood).unwrap();
        assert_eq!((busy.verdict, busy.by.as_deref()), (Verdict::Reject { prohibited: true }, Some("ssh/too-fast")));
        let parts: Vec<(&str, &Part)> = busy.steps.iter().map(|s| (s.path.as_str(), &s.part)).collect();
        assert!(parts.contains(&("ssh", &Part::Shadowed)), "{parts:?}");
        assert!(parts.contains(&("ssh/too-fast", &Part::Decides)), "{parts:?}");
        assert!(parts.contains(&("ssh-watch", &Part::Effects)), "{parts:?}");
        assert!(parts.contains(&("outbound-ok", &Part::NoMatch)), "{parts:?}");
        let too_fast = busy.steps.iter().find(|s| s.path == "ssh/too-fast").unwrap();
        assert_eq!(too_fast.conds[0].1, Some(true));
    }

    #[test]
    fn a_port_nothing_allows_meets_the_default() {
        let judge = Judge::new(&seed()).unwrap();
        let rdp = Conn { local_port: 3389, ..Conn::default() };
        let d = judge.result(&rdp, &no_counts).unwrap();
        assert_eq!((d.layer, d.verdict, d.by), (Layer::Flow, Verdict::Block, None));
        let layers: Vec<Layer> = judge.conn(&rdp, &no_counts).unwrap().iter().map(|d| d.layer).collect();
        assert_eq!(layers, vec![Layer::RawPacket, Layer::Packet, Layer::Flow]);
    }

    #[test]
    fn outgoing_and_loopback_are_allowed() {
        let judge = Judge::new(&seed()).unwrap();
        let out = Conn { inbound: false, remote_port: 443, local_port: 52210, service: Some("peipkg".into()), ..Conn::default() };
        assert_eq!(judge.result(&out, &no_counts).unwrap().verdict, Verdict::Allow);
        let local = Conn { interface: "lo".into(), remote: "127.0.0.1".into(), local_port: 3389, ..Conn::default() };
        assert_eq!(judge.result(&local, &no_counts).unwrap().by.as_deref(), Some("loopback"));
    }

    #[test]
    fn a_rule_conditioned_on_trust_follows_the_network() {
        let mut policy = seed();
        rules::find_mut(&mut policy.flow, "ssh").unwrap().conds.push(Cond::new("Network.Trust", "Equal", &["private"]));
        let judge = Judge::new(&policy).unwrap();
        let mut conn = ssh_from("192.168.1.31");
        conn.network.trust = Some("public".into());
        assert_eq!(judge.result(&conn, &no_counts).unwrap().verdict, Verdict::Block);
        conn.network.trust = Some("private".into());
        assert_eq!(judge.result(&conn, &no_counts).unwrap().verdict, Verdict::Allow);
    }

    #[test]
    fn what_the_machine_refuses_is_refused_here() {
        let mut policy = seed();
        rules::find_mut(&mut policy.flow, "ssh-watch").unwrap().actions = vec!["COUNT(other)".into()];
        let report = check(&policy, &[eth0()]);
        assert!(report.refusals.iter().any(|r| r.contains("no rule counts into “ssh-tries”")), "{:?}", report.refusals);

        let mut policy = seed();
        policy.flow.push(rule("bad", &[("Ttl", "Equal", &["5"])], &["JOIN(default)"]));
        assert!(!check(&policy, &[]).ok());

        let mut policy = seed();
        policy.interface.push(rule("nowhere", &[], &["JOIN(missing)"]));
        let report = check(&policy, &[]);
        assert!(report.refusals.iter().any(|r| r.contains("names no profile")), "{:?}", report.refusals);

        let mut deep = rule("d0", &[], &["PASS"]);
        for i in 1..=13 {
            let mut next = rule(&format!("d{i}"), &[], &[]);
            next.children.push(deep);
            deep = next;
        }
        let mut policy = seed();
        policy.raw.push(deep);
        assert!(check(&policy, &[]).refusals.iter().any(|r| r.contains("nested more than 12")));
    }

    #[test]
    fn two_profiles_at_one_priority_are_a_conflict() {
        let mut policy = seed();
        let mut other = rule("other", &[("Interface.Kind", "Equal", &["wired"])], &["JOIN(default/home)"]);
        other.priority = Some(10);
        policy.interface.push(other);
        let report = check(&policy, &[eth0()]);
        assert!(report.refusals.iter().any(|r| r.contains("On eth0")), "{:?}", report.refusals);
    }

    #[test]
    fn interfaces_join_the_profile_their_rule_names() {
        let mut policy = seed();
        let mut home = rule("home", &[("Network.Name", "Equal", &["Heron Cottage"])], &["JOIN(default/home)"]);
        home.priority = None;
        rules::find_mut(&mut policy.interface, "wired").unwrap().children.push(home);
        let netd = interface_policy(&policy).unwrap();
        let mut subject = eth0();
        assert_eq!(judge_interface(&netd, &subject).0, Verdict::Join("default".into()));
        subject.network.name = Some("Heron Cottage".into());
        let (verdict, by, _) = judge_interface(&netd, &subject);
        assert_eq!((verdict, by.as_deref()), (Verdict::Join("default/home".into()), Some("wired/home")));
    }

    #[test]
    fn the_calendar_is_right() {
        let t = civil(1_791_198_140);
        assert_eq!((t.year, t.month, t.day_of_month), (2026, 10, 5));
        assert_eq!(t.day_of_week, 1);
        assert_eq!(civil(0).day_of_week, 4);
    }
}
