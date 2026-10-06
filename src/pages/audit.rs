//! Auditing: rules with an Audit action write an event each time they
//! decide, at a level; the lowest level recorded is the machine's.

use crate::manager::Manager;
use crate::rules::{self, Layer};
use crate::ui::{example, h, locked, phead, values, LOCKED};

pub fn page(m: &Manager) -> String {
    let may = m.config.may.rules && m.busy.is_none();
    let level = m.config.reporting;
    let levels: String = (1..=6u8)
        .map(|n| {
            let about = match n {
                6 => "Nothing",
                1 => "Everything",
                5 => "Most severe",
                _ => "And above",
            };
            format!(
                r#"<button fx-click="audit-level"{} aria-pressed="{}" class="{}"{}>{}<small>{about}</small></button>"#,
                values(&[("n", &n.to_string())]),
                n == level,
                if level < 6 && n >= level && n < 6 { "rec" } else { "" },
                if may { "" } else { " disabled" },
                if n == 6 { "Off".to_string() } else { n.to_string() }
            )
        })
        .collect();
    let help = match level {
        6 => "No firewall audit events are recorded.".to_string(),
        1 => "Every Audit action is recorded.".to_string(),
        n => format!("Audit actions at level {n} or higher are recorded."),
    };
    let mut auditing = Vec::new();
    for layer in [Layer::Flow, Layer::Packet, Layer::RawPacket, Layer::Interface] {
        for (path, _, rule) in rules::walk(m.config.policy.forest(layer)) {
            if let Some(n) = rule.report() {
                auditing.push((layer, path, n));
            }
        }
    }
    let rows: String = if auditing.is_empty() {
        r#"<tr><td colspan="4" class="muted">No rule has an Audit action. Add one to a rule under Also.</td></tr>"#.into()
    } else {
        auditing
            .iter()
            .map(|(layer, path, n)| {
                format!(
                    r#"<tr class="click" fx-click="rule-open"{}><td class="mono">{}</td><td>{}</td><td class="r">{n}</td><td>{}</td></tr>"#,
                    values(&[("layer", layer.key()), ("p", path)]),
                    h(path),
                    layer.title(),
                    if level < 6 && *n >= level { r#"<span class="tag good dot">Yes</span>"# } else { r#"<span class="tag">No: below the level</span>"# }
                )
            })
            .collect()
    };
    let recorded: Vec<(String, String, u8, String)> = m
        .live
        .events
        .iter()
        .rev()
        .filter(|e| e.effects.reports > 0)
        .filter_map(|e| {
            let layer = match e.layer? {
                ntfe::Layer::Flow => Layer::Flow,
                ntfe::Layer::Packet => Layer::Packet,
                ntfe::Layer::RawPacket => Layer::RawPacket,
            };
            let n = rules::find(m.config.policy.forest(layer), &e.attributed)?.report()?;
            if level >= 6 || n < level {
                return None;
            }
            let t = e.time_ns / 1_000_000_000;
            let civil = crate::engine::civil(t as i64);
            let verdict = match e.verdict {
                Some(ntfe::Verdict::Pass) => "Allowed",
                Some(ntfe::Verdict::Reject(_)) => "Rejected",
                _ => "Blocked",
            };
            Some((format!("{:02}:{:02}:{:02}", civil.hour, civil.minute, civil.second), e.attributed.clone(), n, format!("{verdict} {}/{} from {}", crate::live::protocol_name(e.protocol), e.dst_port, e.src.map(|a| a.to_string()).unwrap_or_default())))
        })
        .take(12)
        .collect();
    let events: String = if recorded.is_empty() {
        r#"<tr><td colspan="4" class="muted">None recorded.</td></tr>"#.into()
    } else {
        recorded.iter().map(|(t, rule, n, what)| format!(r#"<tr><td class="mono">{t} UTC</td><td class="mono">{}</td><td class="r">{n}</td><td>{}</td></tr>"#, h(rule), h(what))).collect()
    };
    format!(
        r#"{}{}<div class="sect"><h2>Record events from level</h2><div class="panel pad"><div class="levels" role="group" aria-label="Lowest level recorded">{levels}</div><div class="acthelp">{help}</div></div></div><div class="sect"><h2>Rules that audit</h2><div class="panel scroll"><table class="tbl"><thead><tr><th>Rule</th><th>Layer</th><th class="r">Level</th><th>Recorded</th></tr></thead><tbody>{rows}</tbody></table></div></div><div class="sect"><h2>Recent events</h2>{}<div class="panel scroll"><table class="tbl"><thead><tr><th>Time</th><th>Rule</th><th class="r">Level</th><th>Event</th></tr></thead><tbody>{events}</tbody></table></div><div class="footnote">Recorded events are in Event Viewer, as ntfe.verdict.reported events.</div></div>"#,
        phead("Auditing", "A rule with an Audit action writes an event to the event log each time it decides. Choose the lowest level recorded.", ""),
        locked(m.config.may.rules, LOCKED),
        example("These events are your real rules judging example traffic: the event stream can't be read by programs yet.")
    )
}
