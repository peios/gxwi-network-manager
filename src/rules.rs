//! Rules as the editors hold them: a layer's forest read from
//! `Machine\System\Network\Rules\<Layer>`, each rule its conditions, its
//! actions, its priority and whether it is on, with its exceptions as its
//! children; and the same rule as the values written back.
//!
//! Nothing here judges a rule. Whether a forest is one the kernel or netd
//! accepts, and what it decides for a connection, are pnp-core's to say
//! (`engine`).

use std::fmt;

use crate::registry::{Tree, Value};
use crate::vocab;

pub const RULES_KEY: &str = "Machine\\System\\Network\\Rules";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Layer {
    Flow,
    Packet,
    RawPacket,
    Interface,
}

impl Layer {
    pub const FIREWALL: [Layer; 3] = [Layer::Flow, Layer::Packet, Layer::RawPacket];

    /// The key name under `Rules`.
    pub fn key(self) -> &'static str {
        match self {
            Layer::Flow => "Flow",
            Layer::Packet => "Packet",
            Layer::RawPacket => "RawPacket",
            Layer::Interface => "Interface",
        }
    }

    pub fn by(key: &str) -> Option<Layer> {
        [Layer::Flow, Layer::Packet, Layer::RawPacket, Layer::Interface].into_iter().find(|l| l.key().eq_ignore_ascii_case(key))
    }

    /// What the person calls it.
    pub fn title(self) -> &'static str {
        match self {
            Layer::Flow => "Connections",
            Layer::Packet => "Packets",
            Layer::RawPacket => "Frames",
            Layer::Interface => "Profile rules",
        }
    }

    pub fn about(self) -> &'static str {
        match self {
            Layer::Flow => "Judged once per connection. Most rules belong here.",
            Layer::Packet => "Every packet, after connection tracking.",
            Layer::RawPacket => "Before connection tracking. Rarely needed.",
            Layer::Interface => "Which profile each interface uses.",
        }
    }

    /// The layer in the vocabulary's terms.
    pub fn bit(self) -> u8 {
        match self {
            Layer::Flow => vocab::FLOW,
            Layer::Packet => vocab::PACKET,
            Layer::RawPacket => vocab::RAW,
            Layer::Interface => vocab::IFACE,
        }
    }

    pub fn core(self) -> pnp_core::Layer {
        match self {
            Layer::Flow => pnp_core::Layer::Flow,
            Layer::Packet => pnp_core::Layer::Packet,
            Layer::RawPacket => pnp_core::Layer::RawPacket,
            Layer::Interface => pnp_core::Layer::Interface,
        }
    }

    pub fn path(self) -> String {
        format!("{RULES_KEY}\\{}", self.key())
    }
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

/// One condition: the value `<fact>.<op>` and what it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cond {
    pub fact: String,
    pub op: String,
    /// The items: one, or several meaning any of them.
    pub items: Vec<String>,
}

impl Cond {
    pub fn new(fact: &str, op: &str, items: &[&str]) -> Cond {
        Cond { fact: fact.into(), op: op.into(), items: items.iter().map(|s| s.to_string()).collect() }
    }

    /// The value name it is written as.
    pub fn key(&self) -> String {
        format!("{}.{}", self.fact, self.op)
    }

    /// The items as a person writes them, joined by commas.
    pub fn text(&self) -> String {
        self.items.join(", ")
    }

    /// The value it is written as: a list when there are several items;
    /// a number where the fact compares numbers and the item is one, as
    /// `Present` always is; else the text.
    pub fn value(&self) -> Value {
        if self.items.len() > 1 {
            return Value::List(self.items.clone());
        }
        let one = self.items.first().cloned().unwrap_or_default();
        let numeric = self.op == "Present" || vocab::lookup(&self.fact).is_some_and(|f| f.family == vocab::Family::Int);
        match one.trim().parse::<i64>() {
            Ok(n) if numeric => Value::Int(n),
            _ => Value::Str(one),
        }
    }
}

/// One rule and its exceptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub name: String,
    pub conds: Vec<Cond>,
    pub actions: Vec<String>,
    /// Its own priority; `None` inherits its parent's, or 0 at a root.
    pub priority: Option<i64>,
    pub enabled: bool,
    /// Values that are neither conditions nor the rule's own, kept as read
    /// so a change to the rule never loses them. pnp-core refuses them.
    pub other: Vec<(String, Value)>,
    pub children: Vec<Rule>,
}

impl Rule {
    pub fn new(name: &str) -> Rule {
        Rule { name: name.into(), conds: Vec::new(), actions: Vec::new(), priority: None, enabled: true, other: Vec::new(), children: Vec::new() }
    }

    pub fn from_tree(tree: &Tree) -> Rule {
        let mut rule = Rule::new(&tree.name);
        for (name, value) in &tree.values {
            if name.eq_ignore_ascii_case("Actions") {
                match value.as_list() {
                    Some(items) => rule.actions = items.into_iter().filter(|a| !a.trim().is_empty()).collect(),
                    None => rule.other.push((name.clone(), value.clone())),
                }
            } else if name.eq_ignore_ascii_case("Priority") {
                match value.as_int() {
                    Some(p) => rule.priority = Some(p),
                    None => rule.other.push((name.clone(), value.clone())),
                }
            } else if name.eq_ignore_ascii_case("Enabled") {
                match value.as_int() {
                    Some(e) => rule.enabled = e != 0,
                    None => rule.other.push((name.clone(), value.clone())),
                }
            } else if let (Some((fact, op)), Some(items)) = (name.rsplit_once('.'), value.as_list()) {
                rule.conds.push(Cond { fact: fact.into(), op: op.into(), items });
            } else {
                rule.other.push((name.clone(), value.clone()));
            }
        }
        rule.children = tree.children.iter().map(Rule::from_tree).collect();
        rule
    }

    /// The rule's own values, as written: its children are their own keys.
    pub fn values(&self) -> Vec<(String, Value)> {
        let mut out: Vec<(String, Value)> = self.conds.iter().map(|c| (c.key(), c.value())).collect();
        if !self.actions.is_empty() {
            out.push(("Actions".into(), Value::List(self.actions.clone())));
        }
        if let Some(p) = self.priority {
            out.push(("Priority".into(), Value::Int(p)));
        }
        if !self.enabled {
            out.push(("Enabled".into(), Value::Int(0)));
        }
        out.extend(self.other.iter().cloned());
        out
    }

    /// The rule as the registry key it is written as, children included.
    pub fn tree(&self) -> Tree {
        Tree { name: self.name.clone(), values: self.values(), children: self.children.iter().map(Rule::tree).collect() }
    }

    /// The verdict among its actions, if it has one.
    pub fn verdict(&self) -> Option<&str> {
        self.actions.iter().map(|a| a.trim()).find(|a| verdict_of(a).is_some())
    }

    /// Its actions that are not its verdict: counting, tagging, auditing.
    pub fn effects(&self) -> Vec<&str> {
        self.actions.iter().map(|a| a.trim()).filter(|a| verdict_of(a).is_none() && !a.eq_ignore_ascii_case("NULL")).collect()
    }

    /// The highest `REPORT` level among its actions.
    pub fn report(&self) -> Option<u8> {
        self.actions.iter().filter_map(|a| call(a).filter(|(n, _)| n.eq_ignore_ascii_case("REPORT")).and_then(|(_, args)| args.first()?.trim().parse().ok())).max()
    }
}

/// A forest: the rules of one layer.
pub type Forest = Vec<Rule>;

pub fn forest(tree: Option<&Tree>) -> Forest {
    tree.map(|t| t.children.iter().map(Rule::from_tree).collect()).unwrap_or_default()
}

/// A rule's path, `/`-separated names from its root.
pub fn find<'a>(forest: &'a [Rule], path: &str) -> Option<&'a Rule> {
    let mut list = forest;
    let mut found = None;
    for part in path.split('/') {
        let rule = list.iter().find(|r| r.name.eq_ignore_ascii_case(part))?;
        list = &rule.children;
        found = Some(rule);
    }
    found
}

pub fn find_mut<'a>(forest: &'a mut Vec<Rule>, path: &str) -> Option<&'a mut Rule> {
    let mut parts = path.split('/');
    let first = parts.next()?;
    let mut rule = forest.iter_mut().find(|r| r.name.eq_ignore_ascii_case(first))?;
    for part in parts {
        rule = rule.children.iter_mut().find(|r| r.name.eq_ignore_ascii_case(part))?;
    }
    Some(rule)
}

/// The list a rule at `path` is in: the forest, or its parent's children.
pub fn siblings_mut<'a>(forest: &'a mut Vec<Rule>, path: &str) -> Option<&'a mut Vec<Rule>> {
    match path.rsplit_once('/') {
        Some((parent, _)) => find_mut(forest, parent).map(|r| &mut r.children),
        None => Some(forest),
    }
}

/// Puts `rule` at `path`: replaces the rule there, keeping its exceptions,
/// or adds it under the parent the path names.
pub fn put(forest: &mut Vec<Rule>, path: &str, mut rule: Rule) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_string();
    rule.name = name.clone();
    let Some(list) = siblings_mut(forest, path) else { return false };
    match list.iter_mut().find(|r| r.name.eq_ignore_ascii_case(&name)) {
        Some(there) => {
            rule.children = std::mem::take(&mut there.children);
            *there = rule;
        }
        None => list.push(rule),
    }
    true
}

pub fn remove(forest: &mut Vec<Rule>, path: &str) -> Option<Rule> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let list = siblings_mut(forest, path)?;
    let at = list.iter().position(|r| r.name.eq_ignore_ascii_case(name))?;
    Some(list.remove(at))
}

/// Every rule with its path and depth, parents before their exceptions.
pub fn walk(forest: &[Rule]) -> Vec<(String, usize, &Rule)> {
    fn go<'a>(list: &'a [Rule], base: &str, depth: usize, out: &mut Vec<(String, usize, &'a Rule)>) {
        for rule in list {
            let path = if base.is_empty() { rule.name.clone() } else { format!("{base}/{}", rule.name) };
            out.push((path.clone(), depth, rule));
            go(&rule.children, &path, depth + 1, out);
        }
    }
    let mut out = Vec::new();
    go(forest, "", 0, &mut out);
    out
}

pub fn count(forest: &[Rule]) -> usize {
    walk(forest).len()
}

/// The deepest rule's depth, a root being 0.
pub fn depth(forest: &[Rule]) -> usize {
    walk(forest).iter().map(|(_, d, _)| *d).max().unwrap_or(0)
}

/// A name a rule may have: what a registry key may be called, and what
/// PNP attributes a decision to.
pub fn check_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("Enter a name.".into());
    }
    if name.contains('/') || name.contains('\\') {
        return Err("A name can't contain / or \\.".into());
    }
    if name.len() > 96 {
        return Err("A name is at most 96 characters.".into());
    }
    Ok(())
}

/// An action as a name and its arguments: `REPORT(3)` is `REPORT`, `["3"]`.
pub fn call(action: &str) -> Option<(&str, Vec<&str>)> {
    let action = action.trim();
    match action.find('(') {
        Some(open) if action.ends_with(')') => {
            let inner = &action[open + 1..action.len() - 1];
            let mut args = Vec::new();
            let mut depth = 0usize;
            let mut start = 0usize;
            for (i, c) in inner.char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => depth = depth.saturating_sub(1),
                    ',' if depth == 0 => {
                        args.push(inner[start..i].trim());
                        start = i + 1;
                    }
                    _ => {}
                }
            }
            args.push(inner[start..].trim());
            Some((action[..open].trim(), args))
        }
        Some(_) => None,
        None => Some((action, Vec::new())),
    }
}

/// A verdict, as the editor knows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block,
    Reject { prohibited: bool },
    Join(String),
    Ignore,
    Down,
}

pub fn verdict_of(action: &str) -> Option<Verdict> {
    let (name, args) = call(action)?;
    let name = name.to_ascii_uppercase();
    Some(match name.as_str() {
        "PASS" => Verdict::Allow,
        "DROP" => Verdict::Block,
        "REJECT" => Verdict::Reject { prohibited: args.first().is_some_and(|a| a.eq_ignore_ascii_case("Prohibited")) },
        "JOIN" => Verdict::Join(args.first().map(|a| a.replace('\\', "/")).unwrap_or_default()),
        "IGNORE" => Verdict::Ignore,
        "DOWN" => Verdict::Down,
        _ => return None,
    })
}

impl Verdict {
    /// As an action is written.
    pub fn action(&self) -> String {
        match self {
            Verdict::Allow => "PASS".into(),
            Verdict::Block => "DROP".into(),
            Verdict::Reject { prohibited: false } => "REJECT(Refused)".into(),
            Verdict::Reject { prohibited: true } => "REJECT(Prohibited)".into(),
            Verdict::Join(profile) => format!("JOIN({profile})"),
            Verdict::Ignore => "IGNORE".into(),
            Verdict::Down => "DOWN".into(),
        }
    }

    /// What a decision of this kind is, as a word for a result.
    pub fn result(&self) -> &'static str {
        match self {
            Verdict::Allow => "Allowed",
            Verdict::Block => "Blocked",
            Verdict::Reject { .. } => "Rejected",
            Verdict::Join(_) => "Joined",
            Verdict::Ignore => "Unmanaged",
            Verdict::Down => "Disabled",
        }
    }

    /// The class a decision of this kind is drawn with.
    pub fn class(&self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Block | Verdict::Down => "block",
            Verdict::Reject { .. } => "reject",
            Verdict::Join(_) => "join",
            Verdict::Ignore => "none",
        }
    }
}

/// What a rule matches, in a line of words.
pub fn summary(conds: &[Cond], layer: Layer) -> String {
    if conds.is_empty() {
        return if layer == Layer::Interface { "All interfaces" } else { "All traffic" }.into();
    }
    let equal = |fact: &str| conds.iter().find(|c| c.fact == fact && c.op == "Equal");
    let mut used: Vec<&Cond> = Vec::new();
    let mut out: Vec<String> = Vec::new();
    if let Some(c) = equal("Direction") {
        used.push(c);
        out.push(if c.items.first().is_some_and(|d| d.eq_ignore_ascii_case("in")) { "Incoming".into() } else { "Outgoing".into() });
    }
    let protocol = equal("Protocol");
    let port = equal("DstPort");
    if protocol.is_some() || port.is_some() {
        let p = protocol.map(|c| c.items.iter().map(|p| protocol_word(p)).collect::<Vec<_>>().join("/")).unwrap_or_default();
        let n = port.map(|c| c.text()).unwrap_or_default();
        out.push([p, n].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" "));
        used.extend(protocol);
        used.extend(port);
    }
    if let Some(c) = equal("Interface.Kind") {
        used.push(c);
        out.push(format!("{} interfaces", c.items.iter().map(|k| capital(k)).collect::<Vec<_>>().join(", ")));
    }
    for c in conds {
        if used.iter().any(|u| std::ptr::eq(*u, c)) {
            continue;
        }
        let v = c.text();
        let eq = c.op == "Equal";
        out.push(match c.fact.as_str() {
            "Interface" if eq && v == "lo" => "Loopback".into(),
            "Network.Trust" if eq => format!("{v} networks"),
            "Network.Name" if eq => format!("on {v}"),
            "SrcAddr" if eq => format!("from {v}"),
            "DstAddr" if eq => format!("to {v}"),
            "Local.Service" if eq => format!("service {v}"),
            "FlowState" if eq => format!("state {v}"),
            "EtherType" if eq => v.to_uppercase(),
            "IcmpType" if eq => format!("ICMP type {v}"),
            "SrcPort" if eq => format!("source port {v}"),
            "Interface" | "Interface.Id" | "Interface.Path" if eq => v,
            fact if fact.starts_with("Counter.") && c.op == "GreaterThan" => counter_words(fact, &v),
            _ => match c.op.as_str() {
                "Present" => format!("{} {}", c.fact, if v.trim() == "0" { "unknown" } else { "known" }),
                "Equal" => format!("{} = {v}", c.fact),
                "GreaterThan" => format!("{} > {v}", c.fact),
                "LessThan" => format!("{} < {v}", c.fact),
                op => format!("{} {} {v}", c.fact, vocab::operator_words(op)),
            },
        });
    }
    out.retain(|s| !s.is_empty());
    out.join(" · ")
}

fn counter_words(fact: &str, limit: &str) -> String {
    let spec = fact.trim_start_matches("Counter.");
    let (name, args) = match spec.split_once('(') {
        Some((n, a)) => (n, a.trim_end_matches(')').split(',').map(|s| s.trim()).collect::<Vec<_>>()),
        None => (spec, Vec::new()),
    };
    let mut words = format!("over {limit} {name}");
    for arg in args {
        match arg {
            "1m" => words.push_str(" a minute"),
            "1h" => words.push_str(" an hour"),
            "1d" => words.push_str(" a day"),
            "SrcAddr" => words.push_str(" per source"),
            "DstAddr" => words.push_str(" per destination"),
            "Interface" => words.push_str(" per interface"),
            "" => {}
            other => words.push_str(&format!(" in {other}")),
        }
    }
    words
}

pub fn protocol_word(p: &str) -> String {
    match p.to_ascii_lowercase().as_str() {
        "tcp" | "6" => "TCP".into(),
        "udp" | "17" => "UDP".into(),
        "icmp" | "1" => "ICMP".into(),
        "icmpv6" | "58" => "ICMPv6".into(),
        "sctp" | "132" => "SCTP".into(),
        _ => p.into(),
    }
}

fn capital(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ssh() -> Rule {
        let mut ssh = Rule::new("ssh");
        ssh.conds = vec![Cond::new("Direction", "Equal", &["in"]), Cond::new("Protocol", "Equal", &["tcp"]), Cond::new("DstPort", "Equal", &["22"])];
        ssh.actions = vec!["PASS".into()];
        let mut fast = Rule::new("too-fast");
        fast.conds = vec![Cond::new("Counter.ssh-tries(1m, SrcAddr)", "GreaterThan", &["10"])];
        fast.actions = vec!["REJECT(Prohibited)".into(), "REPORT(3)".into()];
        ssh.children.push(fast);
        ssh
    }

    #[test]
    fn a_rule_survives_being_written_and_read() {
        let rule = ssh();
        assert_eq!(Rule::from_tree(&rule.tree()), rule);
        let values = rule.values();
        assert!(values.contains(&("DstPort.Equal".into(), Value::Int(22))));
        assert!(values.contains(&("Direction.Equal".into(), Value::Str("in".into()))));
    }

    #[test]
    fn a_rule_is_found_put_and_removed_by_its_path() {
        let mut forest = vec![ssh()];
        assert_eq!(find(&forest, "ssh/too-fast").map(|r| r.report()), Some(Some(3)));
        let mut lan = Rule::new("x");
        lan.actions = vec!["PASS".into()];
        assert!(put(&mut forest, "ssh/lan", lan));
        assert_eq!(count(&forest), 3);
        assert_eq!(depth(&forest), 1);
        let replaced = Rule::new("ignored");
        assert!(put(&mut forest, "ssh", replaced));
        assert_eq!(find(&forest, "ssh").map(|r| r.children.len()), Some(2));
        assert!(remove(&mut forest, "ssh/too-fast").is_some());
        assert_eq!(count(&forest), 2);
    }

    #[test]
    fn rules_are_summed_up_in_words() {
        let rule = ssh();
        assert_eq!(summary(&rule.conds, Layer::Flow), "Incoming · TCP 22");
        assert_eq!(summary(&rule.children[0].conds, Layer::Flow), "over 10 ssh-tries a minute per source");
        assert_eq!(summary(&[], Layer::Interface), "All interfaces");
        assert_eq!(summary(&[Cond::new("Interface.Kind", "Equal", &["wired"])], Layer::Interface), "Wired interfaces");
    }

    #[test]
    fn actions_split_into_a_verdict_and_effects() {
        let rule = &ssh().children[0];
        assert_eq!(rule.verdict().and_then(verdict_of), Some(Verdict::Reject { prohibited: true }));
        assert_eq!(rule.effects(), vec!["REPORT(3)"]);
        assert_eq!(call("TAG(x, Add, 2)").map(|(n, a)| (n.to_string(), a.len())), Some(("TAG".into(), 3)));
        assert_eq!(verdict_of("JOIN(default\\home)"), Some(Verdict::Join("default/home".into())));
    }
}
