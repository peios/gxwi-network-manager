//! The firewall: what is reachable from where (exposure), the rules that
//! decide it, and what it has been deciding (activity).

use std::collections::BTreeMap;

use crate::engine::{self, Conn, Context, Judge, Policy};
use crate::live;
use crate::manager::{Col, Manager, Tab};
use crate::rules::{self, Layer, Rule, Verdict};
use crate::ui::{actions, alert, bar_chart, bytes, decision, duration, example, h, locked, number, phead, ppath, svg, tag, values, LOCKED};

/// What a cell of the exposure matrix shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Allow,
    /// Allowed, with exceptions that refuse some of it.
    Limited,
    Block,
    /// The service takes connections from this machine only.
    NotListening,
}

#[derive(Debug, Clone)]
pub struct Cell {
    pub col: Col,
    pub state: State,
    pub by: Option<String>,
    pub conn: Conn,
}

impl Cell {
    pub fn open(&self) -> bool {
        matches!(self.state, State::Allow | State::Limited)
    }
}

#[derive(Debug, Clone)]
pub struct Row {
    pub title: String,
    pub service: Option<String>,
    pub protocol: String,
    pub port: u16,
    pub cells: Vec<Cell>,
}

pub fn col_title(col: Col) -> &'static str {
    match col {
        Col::Private => "private networks",
        Col::Public => "public networks",
        Col::Local => "this machine",
    }
}

/// A port nothing listens on, to show what happens to the rest.
const ELSEWHERE: u16 = 9999;

/// Every listening service, and whether `policy` lets a new connection
/// reach it from a private network, a public network, and this machine.
pub fn exposure(m: &Manager, policy: &Policy) -> Vec<Row> {
    let Ok(judge) = Judge::new(policy) else { return Vec::new() };
    let interface = m.state.online().or(m.state.interfaces.first());
    let iface = interface.map(|i| i.name().to_string()).unwrap_or_else(|| "eth0".into());
    let here = interface.and_then(|i| i.status.addresses.iter().find(|a| !a.contains(':'))).map(|a| a.split('/').next().unwrap_or_default().to_string()).unwrap_or_else(|| "192.0.2.10".into());
    let mut seen: Vec<(u8, u16)> = Vec::new();
    let mut listeners: Vec<(String, Option<String>, String, u16, bool)> = Vec::new();
    for l in &m.live.listeners {
        if seen.contains(&(l.protocol, l.port)) {
            continue;
        }
        seen.push((l.protocol, l.port));
        listeners.push((live::listener_title(l), live::service(&l.owner).map(String::from), live::protocol_name(l.protocol).into(), l.port, live::loopback_only(l)));
    }
    listeners.push(("Any other port".into(), None, "tcp".into(), ELSEWHERE, false));
    listeners
        .into_iter()
        .map(|(title, service, protocol, port, local_only)| {
            let cells = [Col::Private, Col::Public, Col::Local]
                .into_iter()
                .map(|col| {
                    let conn = match col {
                        Col::Local => Conn { protocol: protocol.clone(), remote: "127.0.0.1".into(), local: "127.0.0.1".into(), local_port: port, interface: "lo".into(), service: service.clone(), ..Conn::default() },
                        _ => Conn {
                            protocol: protocol.clone(),
                            remote: if col == Col::Private { "192.168.1.77".into() } else { "198.51.100.7".into() },
                            local: here.clone(),
                            local_port: port,
                            interface: iface.clone(),
                            network: Context { trust: Some(col.id().into()), ..Context::default() },
                            service: service.clone(),
                            ..Conn::default()
                        },
                    };
                    if local_only && col != Col::Local {
                        return Cell { col, state: State::NotListening, by: None, conn };
                    }
                    let decided = judge.result(&conn, &engine::no_counts);
                    let (state, by) = match decided {
                        Ok(d) if d.passes() => {
                            let narrowed = d.by.as_deref().and_then(|p| rules::find(policy.forest(d.layer), p)).is_some_and(|r| refuses_some(&r.children));
                            (if narrowed { State::Limited } else { State::Allow }, d.by)
                        }
                        Ok(d) => (State::Block, d.by),
                        Err(_) => (State::Block, None),
                    };
                    Cell { col, state, by, conn }
                })
                .collect();
            Row { title, service, protocol, port, cells }
        })
        .collect()
}

fn refuses_some(rules: &[Rule]) -> bool {
    rules.iter().any(|r| r.enabled && (r.verdict().and_then(rules::verdict_of).is_some_and(|v| v != Verdict::Allow) || refuses_some(&r.children)))
}

fn cell_html(cell: &Cell, row: usize) -> String {
    if cell.state == State::NotListening {
        return r#"<span class="dotbtn na">Not listening</span>"#.into();
    }
    let (class, word) = match cell.state {
        State::Allow => ("allow", "Allowed"),
        State::Limited => ("limited", "Limited"),
        _ => ("block", "Blocked"),
    };
    format!(
        r#"<button class="dotbtn {class}" fx-click="cell"{}>{word}</button><span class="cellby">{}</span>"#,
        values(&[("r", &row.to_string()), ("k", cell.col.id())]),
        h(cell.by.as_deref().unwrap_or("default"))
    )
}

/// The live state is the engine's, which only administrators may read.
fn administrators_only(title: &str, what: &str) -> String {
    format!("{}{}", phead(title, "", ""), alert("lock", "lock", &h(what)))
}

pub fn exposure_page(m: &Manager) -> String {
    if !m.config.may.rules {
        return administrators_only("Exposure", "Only administrators can see which services are listening.");
    }
    let rows = exposure(m, &m.config.policy);
    let public: Vec<&Row> = rows.iter().filter(|r| r.service.is_some() && r.cells.iter().any(|c| c.col == Col::Public && c.open())).collect();
    let summary = if public.is_empty() {
        alert("info", "info", "No services can be reached from public networks.")
    } else {
        alert("warn", "warn", &format!("<b>{} service{} reachable from public networks:</b> {}.", public.len(), if public.len() == 1 { " is" } else { "s are" }, public.iter().map(|r| h(&r.title)).collect::<Vec<_>>().join(", ")))
    };
    let body: String = rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let what = match &r.service {
                Some(s) => format!("{} · {}/{}", s, r.protocol, r.port),
                None => "No listener".into(),
            };
            format!(r#"<tr><td><div class="cellmain"><b>{}</b><small class="mono">{}</small></div></td>{}</tr>"#, h(&r.title), h(&what), r.cells.iter().map(|c| format!(r#"<td class="c">{}</td>"#, cell_html(c, i))).collect::<String>())
        })
        .collect();
    format!(
        r#"{}{}{summary}<div class="panel scroll"><table class="tbl matrix"><thead><tr><th>Service</th><th class="col">Private networks</th><th class="col">Public networks</th><th class="col">This machine</th></tr></thead><tbody>{body}</tbody></table></div><div class="footnote">Each cell is judged by this machine's rules, as a new connection from a network of that trust level. Select one to see why, or to change it.</div>"#,
        phead("Exposure", "Services listening on this machine, and where they can be reached from.", ""),
        example("Which services are listening comes from the firewall's live state, which programs can't read yet. The decisions are your real rules.")
    )
}

/// Rules shipped with Peios or its packages, shown as such.
const BUILT_IN: &[(Layer, &str)] = &[
    (Layer::Flow, "outbound-ok"),
    (Layer::Flow, "loopback"),
    (Layer::Flow, "dev-viewer-ports"),
    (Layer::Flow, "gxwi-experimental"),
    (Layer::Flow, "dev-gxwi"),
    (Layer::Flow, "ssh"),
    (Layer::Packet, "tracked"),
    (Layer::Packet, "outbound-ok"),
    (Layer::Packet, "loopback"),
    (Layer::Packet, "arp"),
    (Layer::Packet, "icmpv6-housekeeping"),
    (Layer::Packet, "dhcp-client"),
    (Layer::RawPacket, "all"),
    (Layer::Interface, "wired"),
];

pub fn built_in(layer: Layer, path: &str) -> bool {
    BUILT_IN.iter().any(|(l, n)| *l == layer && *n == path)
}

/// A layer's rules as a table, exceptions under the rule they narrow.
pub fn rule_table(m: &Manager, forest: &[Rule], layer: Layer) -> String {
    let may = m.may_rules();
    let mut rows = String::new();
    fn walk(list: &[Rule], base: &str, depth: usize, inherited: i64, layer: Layer, may: bool, rows: &mut String) {
        for r in list {
            let path = if base.is_empty() { r.name.clone() } else { format!("{base}/{}", r.name) };
            let priority = r.priority.unwrap_or(inherited);
            let open = values(&[("layer", layer.key()), ("p", &path)]);
            *rows += &format!(
                r#"<tr class="click{}" fx-click="rule-open"{open}><td><div class="rname {}">{}{}{}{}</div></td><td class="rsum">{}</td><td class="w">{}</td><td class="r w">{}</td><td class="w"><button class="btn ghost sm rowact" fx-click="rule-child-of"{open}{} title="Add an exception to {}">{}Exception</button></td></tr>"#,
                if r.enabled { "" } else { " off" },
                crate::ui::depth(depth),
                if depth > 0 { r#"<span class="elbow"></span>"# } else { "" },
                h(&r.name),
                if built_in(layer, &path) { r#" <span class="tag outline">Built-in</span>"# } else { "" },
                if r.enabled { "" } else { r#" <span class="tag">Off</span>"# },
                h(&rules::summary(&r.conds, layer)),
                actions(&r.actions, layer),
                match r.priority {
                    Some(p) => p.to_string(),
                    None => format!(r#"<span class="muted" title="{}">{inherited}</span>"#, if depth > 0 { "Inherited" } else { "Default" }),
                },
                if may { "" } else { " disabled" },
                h(&r.name),
                svg("plus")
            );
            walk(&r.children, &path, depth + 1, priority, layer, may, rows);
        }
    }
    walk(forest, "", 0, 0, layer, may, &mut rows);
    if rows.is_empty() {
        rows = r#"<tr><td colspan="5" class="muted">No rules.</td></tr>"#.into();
    }
    format!(r#"<div class="panel scroll"><table class="tbl rtable"><thead><tr><th>Rule</th><th>Matches</th><th>{}</th><th class="r">Priority</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>"#, if layer == Layer::Interface { "Profile" } else { "Action" })
}

pub fn rules_page(m: &Manager) -> String {
    let may = m.may_rules();
    let layer = m.layer;
    let tabs: String = Layer::FIREWALL
        .iter()
        .map(|l| format!(r#"<button role="tab" aria-pressed="{}" fx-click="layer"{}>{} <span class="muted">{}</span></button>"#, *l == layer, values(&[("l", l.key())]), l.title(), rules::count(m.config.policy.forest(*l))))
        .collect();
    let report = engine::check(&m.config.policy, &m.subjects());
    let lints: Vec<&String> = report.lints.iter().filter(|l| rules::walk(m.config.policy.forest(layer)).iter().any(|(p, _, _)| l.contains(&format!("Rule {p}:")))).collect();
    let mut notes = String::new();
    if !report.ok() {
        notes += &alert("bad", "warn", &format!("<b>The machine would refuse these rules:</b> {}", h(&report.refusals.join(" "))));
    }
    if !lints.is_empty() {
        notes += &alert("warn", "warn", &lints.iter().map(|l| h(l)).collect::<Vec<_>>().join("<br>"));
    }
    let extra = format!(
        r#"<button class="btn" fx-click="test-open">{}Test a connection</button><button class="btn primary" fx-click="rule-new"{}{}>{}New rule</button>"#,
        svg("test"),
        values(&[("layer", layer.key())]),
        if may { "" } else { " disabled" },
        svg("plus")
    );
    format!(
        r#"{}{}{notes}<div class="layerbar"><div class="seg" role="tablist">{tabs}</div><span class="note">{}</span></div>{}<div class="footnote">Traffic no rule allows is blocked.</div>"#,
        phead("Firewall rules", "Exceptions sit under the rule they narrow. Order has no effect: the highest priority wins, and a tie goes to the stricter action.", &extra),
        locked(m.config.may.rules, LOCKED),
        layer.about(),
        rule_table(m, m.config.policy.forest(layer), layer)
    )
}

pub fn activity_page(m: &Manager) -> String {
    if !m.config.may.rules {
        return administrators_only("Activity", "Only administrators can see the firewall's decisions and live connections.");
    }
    let now = crate::ui::now();
    let minute = now / 60;
    let mut buckets: Vec<(u64, u64, u64)> = vec![(0, 0, 0); 15];
    for e in &m.live.events {
        let at = e.time_ns / 1_000_000_000 / 60;
        let Some(back) = minute.checked_sub(at) else { continue };
        if back >= 15 {
            continue;
        }
        let b = &mut buckets[14 - back as usize];
        match e.verdict {
            Some(ntfe::Verdict::Pass) => b.0 += 1,
            Some(ntfe::Verdict::Drop) | None => b.1 += 1,
            Some(ntfe::Verdict::Reject(_)) => b.2 += 1,
        }
    }
    let total = |f: fn(&(u64, u64, u64)) -> u64| buckets.iter().map(f).sum::<u64>();
    let chart = format!(
        r#"<div class="sect"><div class="panel pad">{}<div class="legend"><span><i class="good"></i>Allowed {}</span><span><i class="warn"></i>Rejected {}</span><span><i class="bad"></i>Blocked {}</span><span class="muted">New connections a minute</span></div></div></div>"#,
        bar_chart(&buckets),
        number(total(|b| b.0)),
        number(total(|b| b.2)),
        number(total(|b| b.1))
    );
    let tab = m.tab;
    let streams: BTreeMap<&str, Vec<&ntfe::Counter>> = m.live.counters.iter().fold(BTreeMap::new(), |mut map, c| {
        map.entry(c.name.as_str()).or_insert_with(Vec::new).push(c);
        map
    });
    let tabs = format!(
        r#"<div class="layerbar"><div class="seg"><button aria-pressed="{}" fx-click="tab"{}>Connections <span class="muted">{}</span></button><button aria-pressed="{}" fx-click="tab"{}>Counters <span class="muted">{}</span></button></div></div>"#,
        tab == Tab::Connections,
        values(&[("t", "connections")]),
        m.live.flows.len(),
        tab == Tab::Counters,
        values(&[("t", "counters")]),
        streams.len()
    );
    let body = match tab {
        Tab::Connections => {
            let rows: String = m
                .live
                .flows
                .iter()
                .enumerate()
                .map(|(i, f)| {
                    let c = live::conn(f, &m.config, &m.state);
                    let yours = m.state.sessions.iter().any(|s| s.remote == c.remote && s.remote_port == c.remote_port);
                    let network = c.network.id.as_deref().and_then(|id| m.config.network(id)).map(|n| n.title()).unwrap_or_else(|| "—".into());
                    let sentence = f.sentence();
                    let verdict = sentence.and_then(|s| s.verdict).map(|v| match v {
                        ntfe::Verdict::Pass => Verdict::Allow,
                        ntfe::Verdict::Drop => Verdict::Block,
                        ntfe::Verdict::Reject(k) => Verdict::Reject { prohibited: k == ntfe::RejectKind::Prohibited },
                    });
                    let rule = sentence.and_then(|s| live::rule_by_hash(&m.config, s.rule_hash)).map(|(_, p)| p).unwrap_or_else(|| "default".into());
                    format!(
                        r#"<tr class="click" fx-click="flow"{}><td class="w">{}</td><td><div class="cellmain"><b>{}{}</b><small class="mono">{}/{}</small></div></td><td class="mono">{}:{}</td><td>{}</td><td class="w">{}</td><td class="mono small-mono">{}</td><td class="r">{}</td><td class="r">{}</td></tr>"#,
                        values(&[("i", &i.to_string())]),
                        if c.inbound { tag("In", "accent") } else { tag("Out", "") },
                        c.service.as_deref().map(h).unwrap_or_else(|| r#"<span class="muted">No listener</span>"#.into()),
                        if yours { r#" <span class="tag violet">Your session</span>"# } else { "" },
                        h(&c.protocol),
                        c.local_port,
                        h(&c.remote),
                        c.remote_port,
                        h(&network),
                        verdict.as_ref().map(decision).unwrap_or_default(),
                        h(&rule),
                        bytes(f.bytes[0] + f.bytes[1]),
                        duration(now.saturating_sub(f.start_secs))
                    )
                })
                .collect();
            format!(r#"<div class="panel scroll"><table class="tbl"><thead><tr><th></th><th>Local</th><th>Remote</th><th>Network</th><th>Result</th><th>Rule</th><th class="r">Bytes</th><th class="r">Age</th></tr></thead><tbody>{rows}</tbody></table></div>"#)
        }
        Tab::Counters if streams.is_empty() => alert("info", "info", "No rule counts anything. A rule with a Count action keeps a count other rules can read, such as connections a minute from each source."),
        Tab::Counters => streams
            .iter()
            .map(|(name, cells)| {
                let writers: Vec<String> = Layer::FIREWALL.iter().flat_map(|l| rules::walk(m.config.policy.forest(*l)).into_iter().filter(|(_, _, r)| r.actions.iter().any(|a| rules::call(a).is_some_and(|(n, args)| n.eq_ignore_ascii_case("COUNT") && args.first() == Some(name)))).map(|(p, _, _)| p)).collect();
                let limits: Vec<(String, i64)> = Layer::FIREWALL
                    .iter()
                    .flat_map(|l| rules::walk(m.config.policy.forest(*l)))
                    .flat_map(|(p, _, r)| r.conds.iter().filter(|c| c.fact.starts_with(&format!("Counter.{name}")) && c.op == "GreaterThan").filter_map(move |c| Some((p.clone(), c.items.first()?.parse().ok()?))).collect::<Vec<_>>())
                    .collect();
                let global = cells.iter().find(|c| c.src.is_none() && c.dst.is_none());
                let keyed: String = cells
                    .iter()
                    .filter(|c| c.src.is_some())
                    .map(|c| {
                        let minute = c.windows.iter().find(|(w, _)| *w == 60).map(|(_, v)| *v).unwrap_or(0);
                        let over = limits.iter().find(|(_, limit)| minute as i64 > *limit);
                        format!(
                            r#"<tr><td class="mono">{}</td><td class="r">{}</td><td class="r">{}</td><td>{}</td></tr>"#,
                            c.src.map(|a| a.to_string()).unwrap_or_default(),
                            minute,
                            number(c.total),
                            match over {
                                Some((rule, limit)) => format!(r#"<span class="tag warn dot">Over {limit}: {} applies</span>"#, h(rule)),
                                None if !limits.is_empty() => tag("Under the limit", ""),
                                None => String::new(),
                            }
                        )
                    })
                    .collect();
                format!(
                    r#"<div class="sect"><div class="panel"><div class="ins-head"><div class="grow"><h2 class="mono h14">{}</h2><span class="muted">Counted by {}{}</span></div><span class="muted">{} in all</span></div>{}</div></div>"#,
                    h(name),
                    h(&writers.join(", ")),
                    if limits.is_empty() { String::new() } else { format!(" · read by {}", limits.iter().map(|(p, _)| ppath(p)).collect::<Vec<_>>().join(", ")) },
                    number(global.map(|c| c.total).unwrap_or(0)),
                    if keyed.is_empty() { String::new() } else { format!(r#"<table class="tbl"><thead><tr><th>Source</th><th class="r">Last minute</th><th class="r">In all</th><th>State</th></tr></thead><tbody>{keyed}</tbody></table>"#) }
                )
            })
            .collect(),
    };
    format!(
        "{}{}{chart}{tabs}{body}",
        phead("Activity", "What the firewall has been deciding, and the connections open now.", ""),
        example("The firewall's live state can't be read by programs yet. The decisions shown are your real rules judging example traffic.")
    )
}
