//! Name resolution: where a name goes, what resolvd has been doing, and
//! the machine's own servers, domains and names.

use libresolv::Outcome;

use crate::manager::Manager;
use crate::ui::{alert, donut, h, locked, number, phead, values, LOCKED};

fn path(m: &Manager) -> String {
    let l = &m.lookup;
    if l.asking {
        return r#"<div class="path"><div class="step skip"><span class="k">Asking</span><span class="v">…</span></div></div>"#.into();
    }
    let Some(answer) = &l.answer else { return String::new() };
    let a = match answer {
        Ok(a) => a,
        Err(e) => return format!(r#"<div class="gap-top">{}</div>"#, alert("bad", "warn", &format!("resolvd couldn't be asked: {}", h(e)))),
    };
    let step = |k: &str, v: &str, class: &str, small: &str| {
        format!(r#"<div class="step {class}"><span class="k">{k}</span><span class="v">{}</span>{}</div>"#, h(v), if small.is_empty() { String::new() } else { format!("<small>{}</small>", h(small)) })
    };
    let mut steps = String::new();
    match a.source.as_str() {
        "synthetic" => steps += &step("This machine", "Answered", "hit", "Its own name"),
        "hosts" => steps += &step("Static hosts", "Listed", "hit", ""),
        source => {
            steps += &step("Static hosts", "Not listed", "skip", "");
            if source == "cache" {
                steps += &step("Cache", "Hit", "hit", &a.records.first().map(|r| format!("{} s left", r.ttl)).unwrap_or_default());
            } else {
                steps += &step("Cache", "Miss", "skip", "");
                let scope = m.state.resolvd.as_ref().ok().and_then(|r| r.scopes.iter().find(|s| Some(&s.interface) == a.interface.as_ref()));
                let claim = scope.and_then(|s| s.domains.iter().find(|d| l.name == **d || l.name.ends_with(&format!(".{d}"))));
                let why = match claim {
                    Some(d) => format!("claims .{d}"),
                    None => "default route".into(),
                };
                if let Some(i) = &a.interface {
                    steps += &step("Route", i, "hit", &why);
                }
                let failed = a.outcome != Outcome::Found;
                let code = match a.rcode {
                    0 => "NOERROR",
                    2 => "SERVFAIL",
                    3 => "NXDOMAIN",
                    5 => "REFUSED",
                    _ => "",
                };
                steps += &step("Server", a.server.as_deref().unwrap_or("—"), if failed { "hit miss" } else { "hit" }, code);
            }
        }
    }
    let wanted = if l.aaaa { 28 } else { 1 };
    let found: Vec<&str> = a.records.iter().filter(|r| r.rtype == wanted).map(|r| r.text.as_str()).collect();
    let answer = match a.outcome {
        Outcome::Found if !found.is_empty() => found.iter().map(|t| format!(r#"<span class="v">{}</span>"#, h(t))).collect::<String>(),
        Outcome::Found => r#"<span class="v dim">No such record</span>"#.into(),
        Outcome::NotFound => r#"<span class="v bad">No such name</span>"#.into(),
        Outcome::Unavailable => r#"<span class="v bad">No answer</span>"#.into(),
    };
    format!(r#"<div class="path">{steps}<div class="step ans"><span class="k">Answer</span>{answer}</div></div>"#)
}

fn list(m: &Manager, which: &str, label: &str, about: &str, items: &[String], example: &str) -> String {
    let may = m.config.may.dns && m.busy.is_none();
    let chips: String = items
        .iter()
        .enumerate()
        .map(|(i, x)| format!(r#"<span class="chip">{}{}</span>"#, h(x), if may { format!(r#"<button fx-click="dns-del"{} aria-label="Remove {}">×</button>"#, values(&[("k", which), ("i", &i.to_string())]), h(x)) } else { String::new() }))
        .collect();
    format!(
        r#"<div class="row"><div class="lbl"><b>{}</b><small>{}</small></div><div class="listedit">{chips}<form fx-submit="dns-add"{} class="inline-form"><input class="inp mono" name="da-{which}" placeholder="{}" autocomplete="off"{}></form></div></div>"#,
        h(label),
        h(about),
        values(&[("k", which)]),
        h(example),
        if may { "" } else { " disabled" }
    )
}

pub fn page(m: &Manager) -> String {
    let lookup = format!(
        r#"<div class="sect"><h2>Look up a name</h2><div class="panel pad"><form class="lookup" fx-submit="lookup"><input class="inp" name="lk-q" placeholder="example.org" aria-label="Name" autocomplete="off" spellcheck="false"><select class="sel" name="lk-t" aria-label="Record"><option value="A">IPv4 (A)</option><option value="AAAA">IPv6 (AAAA)</option></select><button class="btn primary">Look up</button></form>{}</div></div>"#,
        path(m)
    );
    let (routing, stats) = match &m.state.resolvd {
        Err(e) => (alert("bad", "warn", &format!("resolvd isn't answering: {}", h(e))), String::new()),
        Ok(r) => {
            let mut rows = String::new();
            for s in &r.scopes {
                for d in &s.domains {
                    rows += &format!(r#"<tr><td class="mono">*.{}</td><td>{}</td><td class="mono">{}</td><td class="w muted">Its search domain</td></tr>"#, h(d), h(&s.interface), h(&s.servers.join(", ")));
                }
            }
            for s in r.scopes.iter().filter(|s| s.exclusive) {
                rows += &format!(r#"<tr><td>Every name</td><td>{}</td><td class="mono">{}</td><td class="w"><span class="tag warn">Exclusive</span></td></tr>"#, h(&s.interface), h(&s.servers.join(", ")));
            }
            for s in r.scopes.iter().filter(|s| s.default_route) {
                rows += &format!(r#"<tr><td>All other names</td><td>{}</td><td class="mono">{}</td><td class="w"><span class="tag accent">Default route</span></td></tr>"#, h(&s.interface), h(&s.servers.join(", ")));
            }
            let fallback = if r.fallback_servers.is_empty() { "None".to_string() } else { r.fallback_servers.join(", ") };
            rows += &format!(r#"<tr><td class="muted">If no interface has servers</td><td class="muted">—</td><td class="mono">{}</td><td class="w muted">Fallback</td></tr>"#, h(&fallback));
            let demoted: Vec<String> = r.scopes.iter().flat_map(|s| s.demoted.clone()).collect();
            let demoted = if demoted.is_empty() { String::new() } else { alert("warn", "warn", &format!("Not answering lately, so tried last: {}", h(&demoted.join(", ")))) };
            let routing = format!(r#"<div class="sect"><h2>Where names go</h2>{demoted}<div class="panel scroll"><table class="tbl"><thead><tr><th>Names</th><th>Interface</th><th>Servers</th><th></th></tr></thead><tbody>{rows}</tbody></table></div></div>"#);
            let c = &r.counters;
            let share = if c.queries == 0 { 0.0 } else { c.cache_hits as f64 / c.queries as f64 };
            let may = m.config.may.dns && m.busy.is_none();
            let stats = format!(
                r#"<div class="sect"><h2>Since resolvd started<span class="end"><button class="btn sm" fx-click="flush"{}>Flush cache</button></span></h2><div class="panel pad"><div class="donutwrap">{}<div class="stats"><div class="stat"><span class="k">Questions</span><span class="v">{}</span><small>Answered from the cache: left</small></div><div class="stat"><span class="k">Names cached</span><span class="v">{}</span></div><div class="stat"><span class="k">Asked of servers</span><span class="v">{}</span><small>{} failed</small></div><div class="stat"><span class="k">Answered here</span><span class="v">{}</span><small>Its own name and static hosts</small></div></div></div></div></div>"#,
                if may { "" } else { " disabled" },
                donut(share),
                number(c.queries),
                number(r.cache_entries),
                number(c.upstream_sent),
                number(c.upstream_failed),
                number(c.synthetic)
            );
            (routing, stats)
        }
    };
    let may = m.config.may.dns && m.busy.is_none();
    let off = if may { "" } else { " disabled" };
    let settings = format!(
        r#"<div class="sect"><h2>Settings</h2>{}<div class="panel">{}{}</div></div>"#,
        locked(m.config.may.dns, LOCKED),
        list(m, "fallback", "Fallback servers", "Used only when no interface has DNS servers.", &m.config.fallback, "9.9.9.9"),
        list(m, "extra", "Search domains", "Tried after each interface's own search domains.", &m.config.extra_domains, "corp.example")
    );
    let hosts: String = m
        .config
        .hosts
        .iter()
        .map(|(n, a)| format!(r#"<tr><td class="mono">{}</td><td class="mono">{}</td><td class="w"><button class="x" fx-click="host-del"{}{off} aria-label="Remove {}">×</button></td></tr>"#, h(n), h(a), values(&[("n", n)]), h(n)))
        .collect();
    let hosts = format!(
        r#"<div class="sect"><h2>Static names</h2><div class="panel"><table class="tbl"><thead><tr><th>Name</th><th>Address</th><th></th></tr></thead><tbody>{hosts}</tbody></table><form fx-submit="host-add" class="row addrow"><input class="inp mono" name="hn" placeholder="printer" aria-label="Name" autocomplete="off"{off}><input class="inp mono" name="ha" placeholder="192.168.1.12" aria-label="Address" autocomplete="off"{off}><button class="btn sm"{off}>Add</button><span class="hint">Answered before DNS is asked.</span></form></div></div>"#
    );
    format!(
        "{}{lookup}{routing}{stats}{settings}{hosts}",
        phead("DNS", "Each interface brings its own servers. A name goes to the interface whose domain it ends in, or else to the default route.", "")
    )
}
