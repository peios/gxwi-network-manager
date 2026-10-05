//! Why a connection is allowed or not: the layers it passes in the order
//! the kernel judges them, and in the one shown, each rule's part.

use crate::engine::{Decision, Judge, Part, Step};
use crate::live;
use crate::manager::{Manager, Trace};
use crate::rules::{protocol_word, Layer, Verdict};
use crate::ui::{h, select, values};

fn check(c: &crate::rules::Cond, held: Option<bool>) -> String {
    let op = match c.op.as_str() {
        "Equal" => "=",
        "GreaterThan" => ">",
        "LessThan" => "<",
        other => other,
    };
    let (class, mark) = match held {
        Some(true) => ("ok", " ✓"),
        Some(false) => ("fail", " ✗"),
        None => ("abs", " · n/a"),
    };
    format!(r#"<span class="ck {class}">{} {op} {}{mark}</span>"#, h(&c.fact), h(&c.text()))
}

fn step(s: &Step) -> String {
    let won = s.part == Part::Decides;
    let quiet = matches!(s.part, Part::NoMatch | Part::Off);
    let words = match &s.part {
        Part::Decides => "Decides".to_string(),
        Part::Outranked => "Outranked".to_string(),
        Part::Agrees => "Agrees".to_string(),
        Part::Shadowed => "An exception inside it applies".to_string(),
        Part::Inherits(up) => format!("Matches; {} decides for it", up),
        Part::Effects => "Matches; runs its other actions only".to_string(),
        Part::NoMatch => "No match".to_string(),
        Part::Off => "Turned off".to_string(),
    };
    let what = match (&s.part, &s.verdict) {
        (Part::Decides | Part::Outranked | Part::Agrees, Some(v)) => format!(" · {}{}", v.result().trim_end_matches("ed"), if s.priority != 0 { format!(" · priority {}", s.priority) } else { String::new() }),
        _ => String::new(),
    };
    let fx = if !s.effects.is_empty() && !quiet { format!(" · {}", h(&s.effects.join(", "))) } else { String::new() };
    let checks = if s.conds.is_empty() { String::new() } else { format!(r#"<div class="checks">{}</div>"#, s.conds.iter().map(|(c, held)| check(c, *held)).collect::<String>()) };
    format!(
        r#"<div class="tstep {} {}"><span class="m">{}</span><div><div class="n">{}</div><div class="d2">{}{}{fx}</div>{checks}</div></div>"#,
        if won { "win" } else if quiet { "no" } else { "match" },
        crate::ui::depth(s.depth),
        if won { "✓" } else if quiet { "" } else { "•" },
        h(&s.path),
        h(&words),
        h(&what)
    )
}

pub fn drawer(m: &Manager, t: &Trace) -> String {
    let c = &t.conn;
    let may = m.may_rules();
    let decisions: Result<Vec<Decision>, String> = Judge::new(&m.config.policy).and_then(|j| live::judge(&j, &m.live, c));
    let form = if t.edit {
        let presets: String = [("you", "Your session"), ("public-ssh", "SSH from a café"), ("flood", "SSH flood"), ("stray", "Port 3389"), ("out", "Package download")]
            .iter()
            .map(|(k, l)| format!(r#"<button fx-click="preset"{}>{l}</button>"#, values(&[("k", k)])))
            .collect();
        let mut nets: Vec<(String, String)> = vec![("trust:private".into(), "Any private network".into()), ("trust:public".into(), "Any public network".into()), ("none".into(), "A network with no trust level".into())];
        nets.extend(m.config.networks.iter().filter(|n| n.name.is_some()).map(|n| (n.id.clone(), n.title())));
        nets.push(("lo".into(), "This machine (loopback)".into()));
        let services: Vec<(String, String)> = std::iter::once((String::new(), if c.inbound { "Nothing listening".to_string() } else { "No service".to_string() }))
            .chain(["sshd", "gxwid", "resolvd", "peipkg", "timed", "pnpd", "netd"].iter().map(|s| (s.to_string(), s.to_string())))
            .collect();
        let field = |label: &str, control: String| format!(r#"<label class="fld"><span>{label}</span>{control}</label>"#);
        format!(
            r#"<div class="presets">{presets}</div><div class="tgrid">{}{}{}{}{}{}</div>"#,
            field("Direction", select("t-dir", &[("in".into(), "Incoming".into()), ("out".into(), "Outgoing".into())], true)),
            field("Protocol", select("t-proto", &[("tcp".into(), "TCP".into()), ("udp".into(), "UDP".into()), ("icmp".into(), "ICMP".into())], true)),
            field("Other machine's address", r#"<input class="inp mono" name="t-remote" autocomplete="off">"#.into()),
            field(if c.inbound { "Port here" } else { "Port there" }, r#"<input class="inp mono" name="t-port" inputmode="numeric" autocomplete="off">"#.into()),
            field("Network", select("t-net", &nets, true)),
            field(if c.inbound { "Service here" } else { "Program's service" }, select("t-svc", &services, true))
        )
    } else {
        String::new()
    };
    let network = if c.interface == "lo" {
        "This machine".to_string()
    } else {
        match (&c.network.id, &c.network.name, &c.network.trust) {
            (_, Some(name), Some(trust)) => format!("{name} · {trust}"),
            (_, Some(name), None) => format!("{name} · trust not set"),
            (_, None, Some(trust)) => format!("a {trust} network"),
            _ => "a network with no trust level".into(),
        }
    };
    let local = format!(r#"<div class="end"><b>{}</b><small class="mono">this machine:{}</small></div>"#, h(c.service.as_deref().unwrap_or(if c.inbound { "Nothing listening" } else { "A program" })), c.local_port);
    let remote = format!(r#"<div class="end{}"><b class="mono">{}</b><small>{}</small></div>"#, if c.inbound { "" } else { " r" }, h(&c.remote), h(&network));
    let proto = protocol_word(&c.protocol);
    let card = if c.inbound {
        format!(r#"<div class="conncard">{remote}<div class="mid">{} {}</div>{local}</div>"#, h(&proto), c.local_port)
    } else {
        format!(r#"<div class="conncard">{local}<div class="mid">{} {}</div>{remote}</div>"#, h(&proto), c.remote_port)
    };
    let body = match &decisions {
        Err(why) => format!(r#"{form}{card}<div class="problems">{}</div>"#, h(why)),
        Ok(decisions) => {
            let last = decisions.last().expect("a decision");
            let order = if c.inbound { [Layer::RawPacket, Layer::Packet, Layer::Flow] } else { [Layer::Flow, Layer::Packet, Layer::RawPacket] };
            let shown_layer = t.layer.filter(|l| decisions.iter().any(|d| d.layer == *l)).unwrap_or(last.layer);
            let path: String = order
                .iter()
                .map(|l| match decisions.iter().find(|d| d.layer == *l) {
                    Some(d) => format!(
                        r#"<button class="{}" fx-click="trace-layer"{} aria-pressed="{}"><b>{} · {}</b><small>{}</small></button>"#,
                        d.verdict.class(),
                        values(&[("l", l.key())]),
                        *l == shown_layer,
                        l.title(),
                        d.verdict.result(),
                        h(d.by.as_deref().unwrap_or("no rule: default"))
                    ),
                    None => format!(r#"<button class="skip" disabled><b>{}</b><small>Not reached</small></button>"#, l.title()),
                })
                .collect();
            let why = match &last.by {
                None => format!("No rule in {} allows it.", last.layer.title().to_lowercase()),
                Some(by) => format!(
                    r#"By rule <span class="mono">{}</span> in {}{}"#,
                    h(by),
                    last.layer.title().to_lowercase(),
                    if last.tie {
                        " · the stricter action wins the tie".to_string()
                    } else if last.agreeing > 1 {
                        format!(" · {} rules agree", last.agreeing)
                    } else if last.speakers > 1 {
                        format!(" · highest priority ({})", last.priority)
                    } else {
                        String::new()
                    }
                ),
            };
            let verdict = format!(r#"<div class="verdict {}"><div><div class="big">{}</div><small>{why}</small></div></div>"#, last.verdict.class(), last.verdict.result());
            let shown = decisions.iter().find(|d| d.layer == shown_layer).expect("the shown layer was decided");
            let matched: Vec<&Step> = shown.steps.iter().filter(|s| !matches!(s.part, Part::NoMatch | Part::Off)).collect();
            let quiet: Vec<&Step> = shown.steps.iter().filter(|s| matches!(s.part, Part::NoMatch | Part::Off)).collect();
            let steps = if matched.is_empty() { r#"<div class="empty-line">No rule matches.</div>"#.to_string() } else { matched.iter().map(|s| step(s)).collect() };
            let rest = if quiet.is_empty() { String::new() } else { format!(r#"<details class="more"><summary>{} rule{} didn't match</summary><div class="steps gap-top8">{}</div></details>"#, quiet.len(), if quiet.len() == 1 { "" } else { "s" }, quiet.iter().map(|s| step(s)).collect::<String>()) };
            format!(r#"{form}{card}<div class="layerpath">{path}</div>{verdict}<div class="minihead">Rules in {}</div><div class="steps">{steps}</div>{rest}"#, shown_layer.title().to_lowercase())
        }
    };
    let blocked = decisions.as_ref().map(|d| d.last().is_some_and(|d| d.verdict != Verdict::Allow)).unwrap_or(false);
    let action = match t.cell {
        Some((_, col)) if may => {
            if blocked {
                format!(r#"<button class="btn primary" fx-click="cell-set"{}>Allow from {}</button>"#, values(&[("open", "1")]), super::firewall::col_title(col))
            } else {
                format!(r#"<button class="btn primary" fx-click="cell-set"{}>Block from {}</button>"#, values(&[("open", "0")]), super::firewall::col_title(col))
            }
        }
        _ => String::new(),
    };
    let allow = if t.cell.is_none() && blocked && c.inbound && may { r#"<button class="btn" fx-click="allow-this">Make an allow rule…</button>"# } else { "" };
    let foot = format!(r#"<span class="grow"></span>{allow}<button class="btn" fx-click="close">Close</button>{action}"#);
    super::drawer(&t.title, &body, &foot)
}
