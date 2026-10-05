//! Profile rules: which profile each interface uses. Rules of PNP's
//! interface layer, which netd executes.

use crate::manager::Manager;
use crate::pages::firewall::rule_table;
use crate::rules::Layer;
use crate::ui::{alert, h, locked, phead, ppath, svg, values, LOCKED};

pub fn page(m: &Manager) -> String {
    let rows: String = m
        .state
        .interfaces
        .iter()
        .map(|i| {
            let s = &i.status;
            let dest = match (s.verdict.as_deref(), &s.profile) {
                (Some("JOIN"), Some(p)) => format!(r#"<button class="ppill" fx-click="go-profile"{}>{}</button>"#, values(&[("p", p)]), ppath(p)),
                (Some("DOWN"), _) => r#"<span class="ppill none">Disabled</span>"#.into(),
                _ if s.rule.as_deref().is_some_and(|r| r.contains(" vs ")) => r#"<span class="ppill bad">Rules conflict</span>"#.into(),
                _ => r#"<span class="ppill none">Unmanaged</span>"#.into(),
            };
            let why = match s.rule.as_deref() {
                None | Some("backstop") => "No rule matches".to_string(),
                Some(r) if r.contains(" vs ") => format!("{} tie on priority", r.replace(" vs ", " and ")),
                Some(r) => format!("by {}", r.replace('/', " › ")),
            };
            format!(r#"<div class="arow"><b>{}</b><span class="arrow"></span><span class="dest">{dest}<span class="why">{}</span></span></div>"#, h(&s.name), h(&why))
        })
        .collect();
    let refusal = match &m.state.netd {
        Ok(n) => n.refusal.as_deref().map(|r| alert("warn", "warn", &format!("<b>netd refused the newest rules:</b> {}. The last ones that worked still apply.", h(r)))).unwrap_or_default(),
        Err(e) => alert("bad", "warn", &format!("netd isn't answering: {}", h(e))),
    };
    let extra = format!(r#"<button class="btn primary" fx-click="rule-new"{}{}>{}New rule</button>"#, values(&[("layer", "Interface")]), if m.may_rules() { "" } else { " disabled" }, svg("plus"));
    format!(
        r#"{}{}{refusal}<div class="sect"><h2>Now</h2><div class="panel pad"><div class="assign">{}</div></div></div><div class="sect"><h2>Rules</h2>{}<div class="footnote">Interfaces no rule matches are left unmanaged.</div></div>"#,
        phead("Profile rules", "Which profile each interface uses. The most specific rule that matches applies; priority breaks ties.", &extra),
        locked(m.config.may.rules, LOCKED),
        if rows.is_empty() { r#"<span class="muted">No interfaces.</span>"#.to_string() } else { rows },
        rule_table(m, &m.config.policy.interface, Layer::Interface)
    )
}
