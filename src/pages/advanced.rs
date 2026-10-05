//! What the machine is to DHCP servers, and who may ask netd and resolvd
//! for what.

use crate::machine;
use crate::manager::Manager;
use crate::ui::{h, phead, values};

/// Who a control descriptor lets query and control, in a line.
fn access(m: &Manager, sd: Option<&[u8]>) -> String {
    let Some(sd) = sd else { return "Everyone may look. SYSTEM and Administrators may change. (The built-in default.)".into() };
    let name = |sid: &str| m.config.names.get(sid).cloned().unwrap_or_else(|| sid.to_string());
    let holders = |right: u32| -> String {
        let list: Vec<String> = machine::grants(sd).into_iter().filter(|(_, allows, mask)| *allows && mask & right != 0).map(|(sid, _, _)| name(&sid)).collect();
        if list.is_empty() { "no one".into() } else { list.join(", ") }
    };
    format!("May look: {}. May change: {}.", holders(0x1), holders(0x2))
}

pub fn page(m: &Manager) -> String {
    let may_ids = m.config.may.network_key && m.busy.is_none();
    let off = if may_ids { "" } else { " disabled" };
    let ids: String = m
        .config
        .inventory
        .iter()
        .map(|i| {
            format!(
                r#"<form class="row" fx-submit="client-id"{}><div class="lbl"><b>Client ID: {}</b><small>Derived from the DUID when empty</small></div><input class="inp mono w260"name="cid:{}" placeholder="{}" autocomplete="off"{off}><button class="btn sm"{off}>Save</button></form>"#,
                values(&[("id", &i.id)]),
                h(if i.name.is_empty() { &i.id } else { &i.name }),
                h(&i.id),
                h(i.client_id.as_deref().unwrap_or("Derived"))
            )
        })
        .collect();
    let hostname = match &m.state.netd {
        Ok(n) if !n.hostname.is_empty() => n.hostname.clone(),
        _ => m.config.hostname.clone().unwrap_or_else(|| "Not set".into()),
    };
    format!(
        r#"{}<div class="sect"><h2>DHCP identity</h2><div class="panel"><div class="row"><div class="lbl"><b>DUID</b><small>Identifies this machine to DHCP servers</small></div><span class="mono">{}</span></div>{ids}</div></div><div class="sect"><h2>Access</h2><div class="panel"><div class="row"><div class="lbl"><b>Network configuration (netd)</b><small>{}</small></div><button class="btn sm" fx-click="perm"{}>Permissions…</button></div><div class="row"><div class="lbl"><b>Name resolution (resolvd)</b><small>{}</small></div><button class="btn sm" fx-click="perm"{}>Permissions…</button></div><div class="row"><div class="lbl"><b>Hostname</b><small>Changed in System Settings</small></div><span class="mono">{}</span></div></div></div>"#,
        phead("Advanced", "", ""),
        h(m.config.duid.as_deref().unwrap_or("Not made yet")),
        h(&access(m, m.config.netd_security.as_deref())),
        values(&[("w", "netd")]),
        h(&access(m, m.config.resolvd_security.as_deref())),
        values(&[("w", "resolvd")]),
        h(&hostname)
    )
}
