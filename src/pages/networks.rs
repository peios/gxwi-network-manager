//! Every network this machine has stood on, and what the person says of
//! each: a name, and a trust level, which rules read.

use libgxwi::Fields;

use crate::engine::{self, Context, Judge};
use crate::live;
use crate::manager::Manager;
use crate::ui::{ago, alert, field, h, input, locked, phead, ppath, trust, values, LOCKED};

pub fn page(m: &Manager) -> String {
    let rows: String = m
        .config
        .networks
        .iter()
        .map(|n| {
            let name = match &n.name {
                Some(name) => format!("<b>{}</b>", h(name)),
                None => r#"<b class="muted">Unnamed</b>"#.into(),
            };
            let fresh = if n.is_new() { "<small>New network. Give it a name and a trust level.</small>" } else { "" };
            let seen = match (n.last_seen, &n.last_interface) {
                (Some(t), Some(i)) => format!(r#"{}<span class="muted"> · {}</span>"#, h(&ago(t)), h(i)),
                (Some(t), None) => h(&ago(t)),
                _ => "—".into(),
            };
            let now = m.state.interfaces.iter().any(|i| i.status.carrier && i.status.network.as_deref() == Some(n.id.as_str()));
            format!(
                r#"<tr class="click{}" fx-click="open-network"{}><td><div class="cellmain">{name}{fresh}</div></td><td>{}</td><td class="mono">{}</td><td class="mono">{}</td><td>{}</td></tr>"#,
                if n.is_new() { " hl" } else { "" },
                values(&[("id", &n.id)]),
                trust(n.trust.as_deref()),
                h(n.server.as_deref().or(n.router.as_deref()).unwrap_or("—")),
                h(n.prefixes.first().map(String::as_str).unwrap_or("—")),
                if now { r#"<span class="tag good dot">Connected now</span>"#.to_string() } else { seen }
            )
        })
        .collect();
    let table = if rows.is_empty() {
        alert("info", "info", "No network has been seen yet. One appears here when an interface joins it.")
    } else {
        format!(r#"<div class="panel scroll"><table class="tbl"><thead><tr><th>Name</th><th>Trust</th><th>Identified by</th><th>Subnet</th><th>Last connected</th></tr></thead><tbody>{rows}</tbody></table></div>"#)
    };
    format!(
        "{}{}{table}",
        phead("Networks", "Networks this machine has connected to. Rules can refer to a network's name and trust level.", ""),
        locked(m.config.may.networks, LOCKED)
    )
}

/// What changing a network's name or trust would change: which services
/// it reaches, and which profile its interfaces take.
fn impact(m: &Manager, id: &str, after: &Context) -> Vec<(String, String, String, bool)> {
    let Some(before) = m.config.network(id).map(|n| n.context()) else { return Vec::new() };
    let mut out = Vec::new();
    if let Ok(judge) = Judge::new(&m.config.policy) {
        let interface = m.state.interfaces.iter().find(|i| i.status.network.as_deref() == Some(id)).map(|i| i.name().to_string()).unwrap_or_else(|| "eth0".into());
        for l in m.live.listeners.iter().filter(|l| !live::loopback_only(l)) {
            let conn = |ctx: &Context| engine::Conn {
                protocol: live::protocol_name(l.protocol).into(),
                local_port: l.port,
                interface: interface.clone(),
                network: ctx.clone(),
                service: live::service(&l.owner).map(String::from),
                ..engine::Conn::default()
            };
            let was = judge.result(&conn(&before), &engine::no_counts);
            let will = judge.result(&conn(after), &engine::no_counts);
            if let (Ok(was), Ok(will)) = (was, will)
                && was.passes() != will.passes()
            {
                out.push((format!("{} ({}/{})", live::listener_title(l), live::protocol_name(l.protocol), l.port), was.verdict.result().into(), will.verdict.result().into(), false));
            }
        }
    }
    if let Ok(netd) = engine::interface_policy(&m.config.policy) {
        for i in m.state.interfaces.iter().filter(|i| i.status.network.as_deref() == Some(id)) {
            let mut subject = i.subject(&m.config);
            let was = engine::judge_interface(&netd, &subject).0;
            subject.network = Context { kind: subject.network.kind.clone(), ..after.clone() };
            let will = engine::judge_interface(&netd, &subject).0;
            if was != will {
                let words = |v: &crate::rules::Verdict| match v {
                    crate::rules::Verdict::Join(p) => p.replace('/', " › "),
                    other => other.result().to_string(),
                };
                out.push((format!("{} profile", i.name()), words(&was), words(&will), false));
            }
        }
    }
    for cut in m.cut(&m.config.policy, Some((id, after.clone()))) {
        out.push((format!("Your session: {cut}"), "Allowed".into(), "Blocked".into(), true));
    }
    out
}

pub fn drawer(m: &Manager, id: &str, fields: &Fields) -> String {
    let Some(n) = m.config.network(id) else { return String::new() };
    let may = m.config.may.networks && m.busy.is_none();
    let Some((_, name, trust_now, requested)) = m.network_edit(fields) else { return String::new() };
    let custom = n.trust.as_deref().filter(|t| !matches!(*t, "private" | "public"));
    let radio = |value: &str, label: &str, about: &str| {
        format!(r#"<label><input type="radio" name="n-trust" value="{}"{}>{}<small>{}</small></label>"#, h(value), if may { "" } else { " disabled" }, h(label), h(about))
    };
    let mut choice = crate::vocab::TRUST.iter().map(|(v, l, a)| radio(v, l, a)).collect::<String>();
    if let Some(c) = custom {
        choice += &radio(c, c, "Written in the registry");
    }
    let after = Context { id: Some(id.into()), name: name.clone(), trust: trust_now.clone(), kind: n.kind.clone() };
    let changed_context = name != n.name || trust_now != n.trust;
    let effect = if changed_context {
        let rows = impact(m, id, &after);
        let body = if rows.is_empty() {
            r#"<div class="none">Nothing that rules decide changes.</div>"#.to_string()
        } else {
            rows.iter().map(|(what, from, to, cut)| format!(r#"<div class="ir{}"><span class="grow">{}</span><span>{} <span class="arrowtxt">→</span> <b>{}</b></span></div>"#, if *cut { " cut" } else { "" }, h(what), ppath(from), ppath(to))).collect()
        };
        format!(r#"<div class="impact"><div class="ih">What this changes</div>{body}</div>"#)
    } else {
        String::new()
    };
    let seen = match (n.last_seen, &n.last_interface) {
        (Some(t), Some(i)) => format!("{} on {}", ago(t), i),
        (Some(t), None) => ago(t),
        _ => "—".into(),
    };
    let mut kv = String::new();
    for (k, v) in [("DHCP server", n.server.clone()), ("Router", n.router.clone()), ("Gateway", n.gateway.clone())] {
        if let Some(v) = v {
            kv += &format!(r#"<dt>{k}</dt><dd class="mono">{}</dd>"#, h(&v));
        }
    }
    if !n.prefixes.is_empty() {
        kv += &format!(r#"<dt>Subnets</dt><dd class="mono">{}</dd>"#, n.prefixes.iter().map(|p| h(p)).collect::<Vec<_>>().join("<br>"));
    }
    if !n.dns.is_empty() {
        kv += &format!(r#"<dt>DNS offered</dt><dd class="mono">{}</dd>"#, h(&n.dns.join(", ")));
    }
    kv += &format!(r#"<dt>Record</dt><dd class="mono">{}</dd><dt>Last connected</dt><dd>{}</dd>"#, h(&n.id), h(&seen));
    let body = format!(
        r#"{}<div class="fld"><span>Trust level</span><div class="choice">{choice}</div></div>{effect}<div class="minihead gap">Identified by</div><dl class="kv">{kv}</dl><div class="gap-top16">{}</div>"#,
        field("Name", &input("n-name", "", "Head office", may, " fx-autofocus"), ""),
        field("Preferred address", &input("n-req", "mono", "None", may, ""), "Asked for first when connecting. The DHCP server may give another.")
    );
    let dirty = changed_context || requested != n.requested;
    let cuts = changed_context && impact(m, id, &after).iter().any(|r| r.3);
    let note = if cuts { r#"<span class="grow bad">This change disconnects your session.</span>"# } else if dirty { r#"<span class="grow"></span>"# } else { r#"<span class="grow">No changes.</span>"# };
    let foot = format!(r#"{note}<button class="btn" fx-click="close">Cancel</button><button class="btn primary" fx-click="net-save"{}>Save</button>"#, if dirty && may { "" } else { " disabled" });
    super::drawer(&n.title(), &body, &foot)
}
