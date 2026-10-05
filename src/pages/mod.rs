//! The surface as HTML: the window around every section, and the sections.

pub mod advanced;
pub mod assign;
pub mod audit;
pub mod dns;
pub mod editor;
pub mod firewall;
pub mod networks;
pub mod overview;
pub mod ports;
pub mod profiles;
pub mod trace;

use libgxwi::Fields;

use crate::manager::{Drawer, Manager, Modal, View};
use crate::rules::{self, Layer};
use crate::ui::{h, tile, values};

fn nav(m: &Manager) -> String {
    let item = |view: View, icon: &str, colour: &str, label: &str, badge: String, warn: bool| {
        let badge = if badge.is_empty() { String::new() } else { format!(r#"<span class="badge{}">{}</span>"#, if warn { " warn" } else { "" }, h(&badge)) };
        format!(
            r#"<button fx-click="section"{}{} title="{}">{}<span class="lbl">{}</span>{badge}</button>"#,
            values(&[("section", view.id())]),
            if m.view == view { r#" aria-current="page""# } else { "" },
            h(label),
            tile(icon, colour, true),
            h(label)
        )
    };
    let fresh = m.config.networks.iter().filter(|n| n.is_new()).count();
    let networks = if fresh > 0 { format!("{fresh} new") } else { m.config.networks.len().to_string() };
    let profiles = profiles::nodes(m.config.profiles()).len();
    let public = if m.config.may.rules { firewall::exposure(m, &m.config.policy).iter().filter(|r| r.service.is_some() && r.cells.iter().any(|c| c.col == crate::manager::Col::Public && c.open())).count() } else { 0 };
    let firewall_rules: usize = Layer::FIREWALL.iter().map(|l| rules::count(m.config.policy.forest(*l))).sum();
    let audit = if m.config.reporting >= 6 { "Off".to_string() } else { format!("L{}", m.config.reporting) };
    [
        "<h3>Network</h3>".to_string(),
        item(View::Overview, "map", "teal", "Overview", String::new(), false),
        item(View::Networks, "networks", "teal", "Networks", networks, fresh > 0),
        item(View::Profiles, "profiles", "orange", "Profiles", profiles.to_string(), false),
        item(View::Assign, "assign", "orange", "Profile rules", rules::count(&m.config.policy.interface).to_string(), false),
        item(View::Dns, "dns", "pink", "DNS", String::new(), false),
        "<h3>Firewall</h3>".to_string(),
        item(View::Exposure, "exposure", "red", "Exposure", if public > 0 { format!("{public} public") } else { String::new() }, public > 0),
        item(View::Rules, "rules", "red", "Rules", firewall_rules.to_string(), false),
        item(View::Activity, "activity", "blue", "Activity", String::new(), false),
        "<h3>System</h3>".to_string(),
        item(View::Ports, "ports", "orange", "Port reservations", m.config.reservations.len().to_string(), false),
        item(View::Audit, "audit", "violet", "Auditing", audit, false),
        item(View::Advanced, "advanced", "slate", "Advanced", String::new(), false),
    ]
    .concat()
}

fn keep_bar(m: &Manager) -> String {
    let Some(keep) = &m.keep else { return String::new() };
    let left = keep.until.saturating_duration_since(std::time::Instant::now()).as_secs();
    format!(
        r#"<div class="keepbar" role="status"><span class="grow"><b>Keep this change?</b> {}. Undone in {left} s unless you keep it.</span><progress max="{}" value="{left}"></progress><button class="btn sm" fx-click="revert">Undo</button><button class="btn sm primary" fx-click="keep" fx-autofocus>Keep</button></div>"#,
        h(&keep.what),
        crate::manager::KEEP.as_secs()
    )
}

fn status(m: &Manager) -> String {
    let said = match &m.said {
        Some(Ok(text)) => format!(r#"<span class="said good">{}</span>"#, h(text)),
        Some(Err(text)) => format!(r#"<span class="said bad">{}</span>"#, h(text)),
        None => r#"<span class="said"></span>"#.to_string(),
    };
    let force = match (&m.busy, m.live.engine.refusal) {
        (Some(what), _) => format!(r#"<span class="force busy"><i></i>{}…</span>"#, h(what)),
        (None, Some(errno)) => format!(r#"<span class="force bad"><i></i>Refused (error {errno}): generation {} stands</span>"#, m.live.engine.generation),
        (None, None) => format!(
            r#"<span class="force" title="{}"><i></i>Policy in force · generation {}</span>"#,
            if m.live.example { "Example: the firewall's state can't be read by programs yet" } else { "" },
            m.live.engine.generation
        ),
    };
    format!(r#"<div class="status">{said}{force}</div>"#)
}

fn modal(m: &Manager) -> String {
    let (title, body, go, danger) = match &m.modal {
        None => return String::new(),
        Some(Modal::Cutoff { cut, .. }) => (
            "This change would disconnect you".to_string(),
            format!(
                "<p>The new settings would block this desktop's connection{}: {}.</p><p>If you apply it anyway, it is undone after 30 seconds unless you keep it.</p>",
                if cut.len() > 1 { "s" } else { "" },
                cut.iter().map(|c| format!(r#"<span class="mono">{}</span>"#, h(c))).collect::<Vec<_>>().join(", ")
            ),
            "Apply anyway",
            true,
        ),
        Some(Modal::DeleteRule { path, exceptions, .. }) => (
            format!("Delete {path}?"),
            if *exceptions > 0 {
                format!("<p>Its {} exception{} go with it.</p>", exceptions, if *exceptions == 1 { "" } else { "s" })
            } else {
                "<p>The rule is removed from the registry. Traffic it decided is decided by the rules left.</p>".to_string()
            },
            "Delete",
            true,
        ),
        Some(Modal::DeleteProfile { path }) => (format!("Delete the profile {}?", path.replace('/', " › ")), "<p>Profiles inside it go with it. A rule that names it must be changed first.</p>".to_string(), "Delete", true),
    };
    format!(
        r#"<div class="modal-wrap"><div class="modal" role="alertdialog"><h2>{}</h2>{body}<div class="acts"><button class="btn" fx-click="modal-cancel" fx-key="Escape">Cancel</button><button class="btn {}" fx-click="modal-go">{go}</button></div></div></div>"#,
        h(&title),
        if danger { "danger" } else { "primary" }
    )
}

/// A drawer's frame: its title, body and footer, which are HTML.
pub fn drawer(title: &str, body: &str, foot: &str) -> String {
    format!(
        r#"<div class="scrim" fx-click="close"></div><aside class="drawer" role="dialog" aria-label="{t}"><div class="dh"><h2>{t}</h2><button class="x" fx-click="close" fx-key="Escape" aria-label="Close">×</button></div><div class="db">{body}</div><div class="df">{foot}</div></aside>"#,
        t = h(title)
    )
}

pub fn render(m: &Manager, fields: &Fields) -> String {
    let page = if !m.read {
        format!(r#"<div class="phead"><div class="grow"><h1>Network</h1><p>Reading…</p></div></div>"#)
    } else {
        match m.view {
            View::Overview => overview::page(m),
            View::Networks => networks::page(m),
            View::Profiles => profiles::page(m),
            View::Assign => assign::page(m),
            View::Dns => dns::page(m),
            View::Exposure => firewall::exposure_page(m),
            View::Rules => firewall::rules_page(m),
            View::Activity => firewall::activity_page(m),
            View::Ports => ports::page(m),
            View::Audit => audit::page(m),
            View::Advanced => advanced::page(m),
        }
    };
    let drawer = match &m.drawer {
        None => String::new(),
        Some(Drawer::Network { id }) => networks::drawer(m, id, fields),
        Some(Drawer::Rule(d)) => editor::drawer(m, d),
        Some(Drawer::Trace(t)) => trace::drawer(m, t),
    };
    format!(
        r#"<div class="win">{}<div class="app"><nav class="side" aria-label="Sections">{}</nav><main class="main" id="nm-{}"><div class="page">{page}</div></main>{drawer}{}</div>{}</div>"#,
        keep_bar(m),
        nav(m),
        m.view.id(),
        modal(m),
        status(m)
    )
}
