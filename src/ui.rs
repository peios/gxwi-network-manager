//! What every page is built from: icons, tags, buttons that send events,
//! charts drawn to scale, and the words for times and sizes. Everything is
//! HTML for the surface; text from anywhere goes through [`h`].

use std::fmt::Write as _;

use crate::rules::{self, Layer, Verdict};

pub use libgxwi::escape as h;

/// Line icons on a 24-unit grid.
pub fn path(name: &str) -> &'static str {
    match name {
        "map" => r#"<circle cx="5" cy="12" r="2.5"/><circle cx="19" cy="6" r="2.5"/><circle cx="19" cy="18" r="2.5"/><path d="M7.3 11 16.7 7M7.3 13l9.4 4"/>"#,
        "networks" => r#"<path d="M9 4 3 6v14l6-2 6 2 6-2V4l-6 2z"/><path d="M9 4v14M15 6v14"/>"#,
        "profiles" => r#"<path d="m12 3 9 5-9 5-9-5z"/><path d="m3 13 9 5 9-5"/>"#,
        "assign" => r#"<path d="M4 6h7l3 6h6M4 18h7l3-6"/><path d="m17 9 3 3-3 3"/>"#,
        "dns" => r#"<path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2z"/><path d="M4 19V5M8 7h7M8 11h5"/>"#,
        "exposure" => r#"<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/><path d="m9 12 2 2 4-4"/>"#,
        "rules" => r#"<path d="M8 6h13M8 12h13M8 18h13"/><path d="M3 6h.01M3 12h.01M3 18h.01"/>"#,
        "activity" => r#"<path d="M3 12h4l3-8 4 16 3-8h4"/>"#,
        "advanced" => r#"<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M2 12h3M19 12h3M4.9 19.1 7 17M17 7l2.1-2.1"/>"#,
        "host" => r#"<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>"#,
        "globe" => r#"<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>"#,
        "info" => r#"<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>"#,
        "warn" => r#"<path d="M12 3 2 20h20z"/><path d="M12 10v4M12 17h.01"/>"#,
        "lock" => r#"<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>"#,
        "ports" => r#"<rect x="3" y="7" width="18" height="10" rx="2"/><path d="M7 11v2M11 11v2M15 11v2"/><path d="M8 7V5h8v2"/>"#,
        "audit" => r#"<path d="M9 3h6l1 2h3v16H5V5h3z"/><path d="M9 12l2 2 4-4"/>"#,
        "test" => r#"<path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 1.7 3h10.6a2 2 0 0 0 1.7-3l-5-9V3"/>"#,
        "plus" => r#"<path d="M12 5v14M5 12h14"/>"#,
        "example" => r#"<path d="M4 7h16M4 12h10M4 17h7"/><circle cx="18" cy="16" r="3"/>"#,
        "undo" => r#"<path d="M3 7v6h6"/><path d="M3 13a9 9 0 1 0 3-7.7L3 8"/>"#,
        _ => "",
    }
}

pub fn svg(name: &str) -> String {
    format!(r#"<svg class="ico" viewBox="0 0 24 24" aria-hidden="true">{}</svg>"#, path(name))
}

/// An icon on a tile of its colour, as the nav and the machine have them.
pub fn tile(name: &str, colour: &str, small: bool) -> String {
    format!(r#"<span class="tileicon c-{colour}{}"><svg viewBox="0 0 24 24" aria-hidden="true">{}</svg></span>"#, if small { " sm" } else { "" }, path(name))
}

/// The `fx-value-*` attributes an event carries.
pub fn values(values: &[(&str, &str)]) -> String {
    values.iter().fold(String::new(), |mut out, (k, v)| {
        let _ = write!(out, r#" fx-value-{}="{}""#, k, h(v));
        out
    })
}

/// The class that indents something `depth` levels into a tree: the page
/// refuses style attributes.
pub fn depth(depth: usize) -> String {
    if depth == 0 { String::new() } else { format!("d{}", depth.min(12)) }
}

/// `disabled` when not `enabled`.
pub fn off(enabled: bool) -> &'static str {
    if enabled { "" } else { " disabled" }
}

pub fn phead(title: &str, about: &str, extra: &str) -> String {
    let about = if about.is_empty() { String::new() } else { format!("<p>{}</p>", h(about)) };
    format!(r#"<div class="phead"><div class="grow"><h1>{}</h1>{about}</div>{extra}</div>"#, h(title))
}

/// A line across the page: `kind` is `warn`, `info`, `lock`, `bad` or
/// `example`. `html` is HTML.
pub fn alert(kind: &str, icon: &str, html: &str) -> String {
    format!(r#"<div class="alert {kind}">{}<span class="grow">{html}</span></div>"#, svg(icon))
}

/// Why nothing here can be changed, said once.
pub fn locked(may: bool, why: &str) -> String {
    if may { String::new() } else { alert("lock", "lock", &h(why)) }
}

pub const LOCKED: &str = "You can see these settings. Changing them needs an administrator.";

/// That what follows is example data, and why.
pub fn example(what: &str) -> String {
    alert("example", "example", &format!("<b>Example data.</b> {}", h(what)))
}

pub fn tag(text: &str, class: &str) -> String {
    format!(r#"<span class="tag {class}">{}</span>"#, h(text))
}

/// A network's trust: the two levels offered, or whatever else is written.
pub fn trust(trust: Option<&str>) -> String {
    match trust {
        None => tag("Not set", "dashed"),
        Some("private") => tag("Private", "good"),
        Some("public") => tag("Public", "warn"),
        Some(other) => format!(r#"<span class="tag custom" title="A value set in the registry">{}</span>"#, h(other)),
    }
}

/// A profile path, as a person reads it: `default › home`.
pub fn ppath(path: &str) -> String {
    h(&path.replace('\\', "/").split('/').collect::<Vec<_>>().join(" › "))
}

/// What a rule does: its verdict, then its other actions.
pub fn actions(actions: &[String], layer: Layer) -> String {
    let verdict = actions.iter().find_map(|a| rules::verdict_of(a));
    let main = match (&verdict, layer) {
        (Some(Verdict::Join(p)), _) => format!(r#"<span class="ppill">{}</span>"#, ppath(p)),
        (Some(Verdict::Down), Layer::Interface) => r#"<span class="act block">Disabled</span>"#.into(),
        (Some(Verdict::Ignore), _) => r#"<span class="act none">Unmanaged</span>"#.into(),
        (None, Layer::Interface) => r#"<span class="act none">No profile</span>"#.into(),
        (None, _) => r#"<span class="act none">No verdict</span>"#.into(),
        (Some(Verdict::Allow), _) => r#"<span class="act allow">Allow</span>"#.into(),
        (Some(Verdict::Block | Verdict::Down), _) => r#"<span class="act block">Block</span>"#.into(),
        (Some(Verdict::Reject { .. }), _) => r#"<span class="act reject">Reject</span>"#.into(),
    };
    let effects: String = actions
        .iter()
        .filter(|a| rules::verdict_of(a).is_none() && !a.trim().eq_ignore_ascii_case("NULL"))
        .map(|a| format!(r#"<span class="fx">{}</span>"#, h(&effect_words(a))))
        .collect();
    main + &effects
}

/// An effect, short: `Count ssh-tries`, `Audit L3`.
pub fn effect_words(action: &str) -> String {
    match rules::call(action) {
        Some((name, args)) => match name.to_ascii_uppercase().as_str() {
            "COUNT" => format!("Count {}", args.first().copied().unwrap_or_default()),
            "TAG" => format!("Tag {}", args.first().copied().unwrap_or_default()),
            "REPORT" => format!("Audit L{}", args.first().copied().unwrap_or_default()),
            "PROMPT" => format!("Prompt {}", args.first().copied().unwrap_or_default()),
            other => other.to_string(),
        },
        None => action.to_string(),
    }
}

/// A verdict as a decision's word, in its colour.
pub fn decision(verdict: &Verdict) -> String {
    format!(r#"<span class="act {}">{}</span>"#, verdict.class(), verdict.result())
}

/// "3 h 12 min", "40 min", "1 min".
pub fn duration(secs: u64) -> String {
    if secs >= 86_400 {
        format!("{} d {} h", secs / 86_400, secs % 86_400 / 3600)
    } else if secs >= 3600 {
        format!("{} h {} min", secs / 3600, secs % 3600 / 60)
    } else if secs >= 60 {
        format!("{} min", secs / 60)
    } else {
        format!("{secs} s")
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// When something was last seen, as a person says it.
pub fn ago(epoch: i64) -> String {
    let secs = (now() as i64 - epoch).max(0) as u64;
    match secs {
        0..=89 => "Just now".into(),
        90..=3599 => format!("{} min ago", secs / 60),
        3600..=86_399 => format!("{} h ago", secs / 3600),
        86_400..=172_799 => "Yesterday".into(),
        172_800..=1_209_599 => format!("{} days ago", secs / 86_400),
        _ => format!("{} weeks ago", secs / 604_800),
    }
}

pub fn bytes(n: u64) -> String {
    match n {
        0..=999 => format!("{n} B"),
        1000..=999_999 => format!("{:.1} kB", n as f64 / 1e3),
        1_000_000..=999_999_999 => format!("{:.1} MB", n as f64 / 1e6),
        _ => format!("{:.2} GB", n as f64 / 1e9),
    }
}

pub fn rate(bytes_per_sec: f64) -> String {
    format!("{}/s", bytes(bytes_per_sec.max(0.0) as u64))
}

/// A whole number with thousands separated.
pub fn number(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Several series over time, as filled lines. Each series' points are
/// spread evenly across the width; the scale is the largest value.
pub fn area_chart(series: &[(&[f64], &str)], height: u32) -> String {
    let width = 400.0;
    let h = f64::from(height);
    let max = series.iter().flat_map(|(s, _)| s.iter().copied()).fold(0.0f64, f64::max).max(1.0) * 1.15;
    let mut out = format!(r#"<svg class="chart" viewBox="0 0 400 {height}" preserveAspectRatio="none" height="{height}" aria-hidden="true">"#);
    for g in [0.33, 0.66] {
        let _ = write!(out, r#"<line x1="0" x2="400" y1="{y:.1}" y2="{y:.1}" stroke="var(--border-subtle)" stroke-width="1"/>"#, y = h * g);
    }
    for (points, colour) in series {
        if points.len() < 2 {
            continue;
        }
        let step = width / (points.len() - 1) as f64;
        let line: String = points.iter().enumerate().map(|(i, v)| format!("{}{:.1} {:.1}", if i == 0 { "M" } else { "L" }, i as f64 * step, h - v / max * (h - 4.0))).collect();
        let _ = write!(out, r#"<path d="{line}L400 {h}L0 {h}Z" fill="{colour}" fill-opacity="0.12"/><path d="{line}" fill="none" stroke="{colour}" stroke-width="1.6" vector-effect="non-scaling-stroke"/>"#);
    }
    out + "</svg>"
}

/// Stacked bars per minute: allowed, blocked, rejected. Labels every five
/// bars, with the last bar "now".
pub fn bar_chart(bars: &[(u64, u64, u64)]) -> String {
    let n = bars.len().max(1);
    let (w, h) = (600.0, 110.0);
    let bw = w / n as f64;
    let max = bars.iter().map(|(a, b, c)| a + b + c).max().unwrap_or(1).max(1) as f64 * 1.1;
    let mut out = format!(r#"<svg class="bars" viewBox="0 0 {w} {h}" preserveAspectRatio="none" aria-hidden="true">"#);
    for (i, (allowed, blocked, rejected)) in bars.iter().enumerate() {
        let mut y = h - 14.0;
        for (v, colour) in [(*allowed, "var(--good)"), (*blocked, "var(--bad)"), (*rejected, "var(--warn)")] {
            let height = v as f64 / max * (h - 18.0);
            y -= height;
            let _ = write!(out, r#"<rect x="{:.1}" y="{y:.1}" width="{:.1}" height="{height:.1}" fill="{colour}" rx="1.5"/>"#, i as f64 * bw + 3.0, (bw - 6.0).max(1.0));
        }
        if i % 5 == 0 || i == n - 1 {
            let label = if i == n - 1 { "now".to_string() } else { format!("−{} min", n - 1 - i) };
            let _ = write!(out, r#"<text x="{:.1}" y="{}" text-anchor="middle" font-size="9.5" fill="var(--text-muted)" font-family="Manrope, sans-serif">{label}</text>"#, i as f64 * bw + bw / 2.0, h - 2.0);
        }
    }
    out + "</svg>"
}

/// A share, as a ring with its percentage.
pub fn donut(share: f64) -> String {
    let r = 34.0;
    let c = 2.0 * std::f64::consts::PI * r;
    let share = share.clamp(0.0, 1.0);
    format!(
        r#"<svg class="donut" viewBox="0 0 84 84" aria-hidden="true"><circle cx="42" cy="42" r="{r}" fill="none" stroke="var(--surface-2)" stroke-width="10"/><circle cx="42" cy="42" r="{r}" fill="none" stroke="var(--accent-solid)" stroke-width="10" stroke-dasharray="{:.1} {c:.1}" transform="rotate(-90 42 42)" stroke-linecap="round"/><text x="42" y="47" text-anchor="middle" font-size="15" font-weight="700" fill="var(--text-primary)" font-family="Manrope, sans-serif">{}%</text></svg>"#,
        c * share,
        (share * 100.0).round()
    )
}

/// A labelled field over its control.
pub fn field(label: &str, control: &str, help: &str) -> String {
    let help = if help.is_empty() { String::new() } else { format!(r#"<span class="help">{}</span>"#, h(help)) };
    format!(r#"<label class="fld"><span>{}</span>{control}{help}</label>"#, h(label))
}

/// A text field named `name`.
pub fn input(name: &str, class: &str, placeholder: &str, enabled: bool, extra: &str) -> String {
    format!(r#"<input class="inp {class}" name="{}" placeholder="{}" autocomplete="off" spellcheck="false"{}{extra}>"#, h(name), h(placeholder), off(enabled))
}

/// A choice named `name` among `(value, label)`s.
pub fn select(name: &str, options: &[(String, String)], enabled: bool) -> String {
    let opts: String = options.iter().map(|(v, l)| format!(r#"<option value="{}">{}</option>"#, h(v), h(l))).collect();
    format!(r#"<select class="sel" name="{}"{}>{opts}</select>"#, h(name), off(enabled))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_and_times_read_as_a_person_says_them() {
        assert_eq!(number(1284), "1,284");
        assert_eq!(number(12), "12");
        assert_eq!(number(1_000_000), "1,000,000");
        assert_eq!(duration(72_840), "20 h 14 min");
        assert_eq!(duration(59), "59 s");
        assert_eq!(bytes(18_400_000), "18.4 MB");
    }

    #[test]
    fn a_rule_reads_as_its_verdict_then_its_effects() {
        let html = actions(&["REJECT(Prohibited)".into(), "REPORT(3)".into()], Layer::Flow);
        assert!(html.contains("Reject") && html.contains("Audit L3"));
        assert!(actions(&["JOIN(default\\home)".into()], Layer::Interface).contains("default › home"));
    }
}
