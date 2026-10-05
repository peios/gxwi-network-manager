//! The machine at a glance: each interface, the profile it stands in, the
//! network on the other side, and whether that leads out; then the
//! interface chosen, in full.

use libnetd::Level;

use crate::machine::{Interface, Source};
use crate::manager::Manager;
use crate::ui::{alert, area_chart, duration, h, phead, ppath, rate, svg, tag, tile, trust, values};

fn v4(i: &Interface) -> Option<&str> {
    i.status.addresses.iter().find(|a| !a.contains(':')).map(String::as_str)
}

fn lane(m: &Manager, i: &Interface) -> String {
    let s = &i.status;
    let joined = i.joined();
    let on = s.carrier && joined;
    let status = if !joined && s.verdict.as_deref() != Some("DOWN") {
        "Unmanaged".to_string()
    } else if s.verdict.as_deref() == Some("DOWN") {
        "Disabled".to_string()
    } else if !s.carrier {
        "No cable".to_string()
    } else {
        v4(i).map(|a| a.split('/').next().unwrap_or(a).to_string()).unwrap_or_else(|| "Connecting".into())
    };
    let node = format!(
        r#"<button class="node" fx-click="select"{} aria-pressed="{}"><span class="t"><span class="st{}"></span>{}</span><small class="{}">{}</small></button>"#,
        values(&[("i", &s.name)]),
        m.selected.as_deref() == Some(s.name.as_str()),
        if on { " on" } else { "" },
        h(&s.name),
        if on { "mono" } else { "" },
        h(&status)
    );
    let profile = s.profile.as_deref().map(|p| format!(r#"<button class="wl" fx-click="go-profile"{} title="Profile">{}</button>"#, values(&[("p", p)]), ppath(p))).unwrap_or_default();
    let network = match s.network.as_deref().and_then(|id| m.config.network(id)) {
        Some(n) if s.carrier => format!(r#"<button class="node" fx-click="open-network"{}><span class="t">{}</span><small>{}</small></button>"#, values(&[("id", &n.id)]), h(&n.title()), trust(n.trust.as_deref())),
        _ => {
            let (title, about) = if !joined {
                ("Not managed", if i.kind == "wireless" { "Wi-Fi isn't supported yet" } else { "No rule assigns a profile" })
            } else if s.carrier {
                ("Looking", "No network answered yet")
            } else {
                ("No network", "Waiting for a link")
            };
            format!(r#"<div class="node ghost"><span class="t">{title}</span><small>{about}</small></div>"#)
        }
    };
    let routed = s.level == Level::Routed;
    let out = if routed { format!(r#"<div class="node inet">{}<small>via {}</small></div>"#, svg("globe"), h(s.gateway.as_deref().or(s.gateway6.as_deref()).unwrap_or("a router"))) } else { "<span></span>".into() };
    format!(r#"<div class="lane">{node}<div class="wire{}">{profile}</div>{network}<div class="wire{}"></div>{out}</div>"#, if on { " on" } else { "" }, if routed { " on" } else { "" })
}

fn lease(i: &Interface) -> String {
    let Some(l) = &i.status.lease else { return String::new() };
    let state = l.state.to_ascii_lowercase();
    // The lease's whole span, how much of it has gone, and where the client
    // starts renewing and rebinding; a netd too old to say gets the stages.
    if l.duration > 0 {
        let used = l.duration.saturating_sub(l.expires_in);
        let at = |secs: u64| ((secs as f64 / l.duration as f64) * 100.0).round().clamp(0.0, 100.0) as u32;
        let stage = match state.as_str() {
            "renewing" => r#" <span class="tag warn">Renewing</span>"#,
            "rebinding" => r#" <span class="tag bad">Rebinding</span>"#,
            _ => "",
        };
        return format!(
            r#"<div class="minihead gap">DHCP lease{stage}</div><div class="leasebar"><progress max="{}" value="{used}"></progress><b class="at{}"><span>Renew</span></b><b class="at{}"><span>Rebind</span></b></div><div class="leaselbl"><span>Obtained {} ago from {}</span><span>Expires in {}</span></div>"#,
            l.duration,
            at(l.renew_at),
            at(l.rebind_at),
            duration(used),
            h(&l.server),
            duration(l.expires_in)
        );
    }
    let step = |name: &str, about: &str| format!(r#"<span class="{}">{}<small>{}</small></span>"#, if state.starts_with(&name.to_ascii_lowercase()) { "on" } else { "" }, name, about);
    format!(
        r#"<div class="minihead gap">DHCP lease</div><div class="leasesteps">{}{}{}</div><div class="leaselbl"><span>From {}</span><span>Expires in {}</span></div>"#,
        step("Bound", "Holding the address"),
        step("Renewing", "Asking its server"),
        step("Rebinding", "Asking any server"),
        h(&l.server),
        duration(l.expires_in)
    )
}

fn inspector(m: &Manager, i: &Interface) -> String {
    let s = &i.status;
    let may = m.config.may.network_key && m.busy.is_none();
    let state = if s.verdict.as_deref() == Some("DOWN") {
        tag("Disabled", "")
    } else if !i.joined() {
        tag("Unmanaged", "")
    } else if s.carrier {
        tag(&match i.speed {
            Some(mb) if mb >= 1000 => format!("Connected · {} Gb/s", mb / 1000),
            Some(mb) => format!("Connected · {mb} Mb/s"),
            None => "Connected".into(),
        }, "good dot")
    } else {
        tag("Disconnected", "dot")
    };
    let renewing = m.renewing.as_deref() == Some(s.name.as_str());
    let mut buttons = String::new();
    if s.lease.is_some() {
        buttons += &format!(r#"<button class="btn sm" fx-click="renew"{}{}>{}</button>"#, values(&[("i", &s.name)]), if may && !renewing { "" } else { " disabled" }, if renewing { "Renewing…" } else { "Renew lease" });
    }
    if i.joined() {
        buttons += &format!(r#"<button class="btn sm" fx-click="reconcile" title="Make every interface match its profile again"{}>Reapply</button>"#, if may && m.renewing.is_none() { "" } else { " disabled" });
    }
    let head = format!(
        r#"<div class="ins-head"><div class="grow"><h2>{}</h2><span class="muted">{} · {}</span></div>{state}{buttons}</div>"#,
        h(&s.name),
        h(if s.driver.is_empty() { &i.kind } else { &s.driver }),
        h(if s.path.is_empty() { &s.mac } else { &s.path })
    );
    let network = s.network.as_deref().and_then(|id| m.config.network(id));
    let config = format!(
        r#"<div class="minihead{}">Configuration</div><div class="linkrow"><span class="k">Profile</span><span class="v">{}</span></div><div class="linkrow"><span class="k">Rule</span><span class="v">{}</span></div><div class="linkrow"><span class="k">Network</span><span class="v">{}</span></div>"#,
        if s.carrier { " gap" } else { "" },
        match &s.profile {
            Some(p) => format!(r#"<button class="ppill" fx-click="go-profile"{}>{}</button>"#, values(&[("p", p)]), ppath(p)),
            None => r#"<span class="ppill none">None</span>"#.into(),
        },
        match s.rule.as_deref() {
            None | Some("backstop") => r#"<span class="muted">No rule matches</span>"#.into(),
            Some(r) if r.contains(" vs ") => format!(r#"<span class="ppill bad" title="Rules tie on priority">{}</span>"#, h(r)),
            Some(r) => format!(r#"<button class="btn ghost sm" fx-click="go"{}>{}</button>"#, values(&[("view", "assign")]), ppath(r)),
        },
        match network {
            Some(n) => format!(r#"<button class="btn ghost sm" fx-click="open-network"{}>{}</button> {}"#, values(&[("id", &n.id)]), h(&n.title()), trust(n.trust.as_deref())),
            None => r#"<span class="muted">None</span>"#.into(),
        }
    );
    let warning = s.warning.as_deref().map(|w| alert("warn", "warn", &h(w))).unwrap_or_default();
    if !s.carrier || !i.joined() {
        let assign = if !i.joined() {
            format!(r#"<div class="gap-top"><button class="btn sm" fx-click="rule-new-for"{}{}>{}Assign a profile</button></div>"#, values(&[("i", &s.name)]), if m.may_rules() { "" } else { " disabled" }, svg("plus"))
        } else {
            String::new()
        };
        return format!(
            r#"<div class="panel inspector">{head}<div class="ins-body"><div>{warning}<dl class="kv"><dt>MAC</dt><dd class="mono">{}</dd><dt>Bus</dt><dd class="mono">{}</dd><dt>Driver</dt><dd class="mono">{}</dd><dt>Interface ID</dt><dd class="mono">{}</dd></dl></div><div>{config}{assign}</div></div></div>"#,
            h(&s.mac),
            h(&s.path),
            h(&s.driver),
            h(&s.ifid)
        );
    }
    let mut kv = String::new();
    let mut first4 = true;
    let mut first6 = true;
    for a in &i.addresses {
        let six = a.cidr.contains(':');
        let label = match (six, a.source) {
            (_, Source::LinkLocal) => "Link-local",
            (false, _) if first4 => "IPv4",
            (true, _) if first6 => "IPv6",
            _ => "",
        };
        if a.source != Source::LinkLocal {
            if six { first6 = false } else { first4 = false }
        }
        let note = if a.deprecated { r#"<span class="note old">Deprecated</span>"#.to_string() } else if a.source.words().is_empty() { String::new() } else { format!(r#"<span class="note">{}</span>"#, a.source.words()) };
        kv += &format!(r#"<dt>{label}</dt><dd class="mono">{}{note}</dd>"#, h(&a.cidr));
    }
    let metric = i.routes.iter().find(|r| r.destination == "default").map(|r| format!(r#"<span class="note">metric {}</span>"#, r.metric)).unwrap_or_default();
    let gateways: Vec<&str> = [s.gateway.as_deref(), s.gateway6.as_deref()].into_iter().flatten().collect();
    if !gateways.is_empty() {
        kv += &format!(r#"<dt>Gateway</dt><dd class="mono">{}{metric}</dd>"#, h(&gateways.join(" · ")));
    }
    if !s.dns.is_empty() {
        let search = if s.search.is_empty() { String::new() } else { format!(r#"<span class="note">search {}</span>"#, h(&s.search.join(", "))) };
        kv += &format!(r#"<dt>DNS</dt><dd class="mono">{}{search}</dd>"#, h(&s.dns.join(", ")));
    }
    if let Some(mtu) = i.mtu {
        kv += &format!(r#"<dt>MTU</dt><dd class="mono">{mtu}</dd>"#);
    }
    kv += &format!(r#"<dt>MAC</dt><dd class="mono">{}</dd>"#, h(&s.mac));
    let samples = m.traffic.get(&s.name);
    let rx: Vec<f64> = samples.map(|q| q.iter().map(|(r, _)| *r).collect()).unwrap_or_default();
    let tx: Vec<f64> = samples.map(|q| q.iter().map(|(_, t)| *t).collect()).unwrap_or_default();
    let traffic = if rx.len() >= 2 {
        format!(
            r#"{}<div class="legend"><span><i class="accent"></i>Received {}</span><span><i class="violet"></i>Sent {}</span><span class="muted">Last {} s</span></div>"#,
            area_chart(&[(&rx, "var(--accent-solid)"), (&tx, "var(--violet)")], 72),
            rate(*rx.last().unwrap_or(&0.0)),
            rate(*tx.last().unwrap_or(&0.0)),
            (rx.len() * 2).min(60)
        )
    } else {
        r#"<div class="measuring">Measuring…</div>"#.to_string()
    };
    let routes = if i.routes.is_empty() {
        String::new()
    } else {
        format!(
            r#"<div class="minihead gap">Routes</div><dl class="kv">{}</dl>"#,
            i.routes.iter().map(|r| format!(r#"<dt class="mono">{}</dt><dd class="mono">{}<span class="note">metric {}</span></dd>"#, h(&r.destination), h(r.via.as_deref().unwrap_or("on the link")), r.metric)).collect::<String>()
        )
    };
    format!(
        r#"<div class="panel inspector">{head}<div class="ins-body"><div>{warning}<div class="minihead">Addresses</div><dl class="kv">{kv}</dl>{}</div><div><div class="minihead">Traffic</div>{traffic}{config}{routes}</div></div></div>"#,
        lease(i)
    )
}

pub fn page(m: &Manager) -> String {
    let st = &m.state;
    let online = st.online();
    let mut alerts = String::new();
    match &st.netd {
        Err(e) => alerts += &alert("bad", "warn", &format!("<b>netd isn't answering.</b> What is shown is what it last recorded. {}", h(e))),
        Ok(n) => {
            if let Some(why) = &n.refusal {
                alerts += &alert("warn", "warn", &format!("<b>The newest profile rules were refused:</b> {}. The last ones that worked still apply.", h(why)));
            }
        }
    }
    if let Some(e) = &m.config.error {
        alerts += &alert("bad", "warn", &format!("The configuration couldn't all be read: {}", h(e)));
    }
    let dns: Vec<String> = match &st.resolvd {
        Ok(r) => r.scopes.iter().flat_map(|s| s.servers.clone()).collect(),
        Err(_) => st.interfaces.iter().flat_map(|i| i.status.dns.clone()).collect(),
    };
    let named = match &st.netd {
        Ok(n) if !n.hostname.is_empty() => Some(n.hostname.clone()),
        _ => m.config.hostname.clone(),
    };
    let hostname = named.clone().unwrap_or_else(|| "Not set".into());
    let cell = |k: &str, v: &str, mono: bool| format!(r#"<div><span class="k">{k}</span><span class="v{}">{}</span></div>"#, if mono { " mono" } else { "" }, h(v));
    let summary = [
        cell("Status", match st.netd.as_ref().map(|n| n.level) {
            Ok(Level::Routed) => "Connected",
            Ok(Level::Addressed) => "Local network only",
            Ok(Level::Link) => "Connecting",
            _ => "Offline",
        }, false),
        cell("IPv4", online.and_then(v4).unwrap_or("—"), true),
        cell("Gateway", online.and_then(|i| i.status.gateway.as_deref()).unwrap_or("—"), true),
        cell("DNS", &if dns.is_empty() { "—".to_string() } else { dns.join(", ") }, true),
        cell("Hostname", &hostname, true),
    ]
    .concat();
    let lanes: String = st.interfaces.iter().map(|i| lane(m, i)).collect();
    let lanes = if lanes.is_empty() { r#"<div class="node ghost"><span class="t">No interfaces</span><small>netd has found none</small></div>"#.to_string() } else { lanes };
    let selected = m.selected.as_deref().and_then(|s| st.interface(s)).map(|i| inspector(m, i)).unwrap_or_default();
    format!(
        r#"{}{alerts}<div class="summary">{summary}</div><div class="panel"><div class="topo"><div class="host">{}<b>{}</b><small>{}</small></div><div class="lanes{}">{lanes}</div></div></div>{selected}"#,
        phead("Overview", "", ""),
        tile("host", "slate", false),
        h(named.as_deref().unwrap_or("This machine")),
        if named.is_some() { "This machine" } else { "No hostname" },
        if st.interfaces.len() == 1 { " one" } else { "" }
    )
}
