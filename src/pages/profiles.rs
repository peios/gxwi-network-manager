//! Profiles: how an interface stands on a network. A profile inside another
//! inherits every setting and overrides only what it sets, so each setting
//! is shown down the chain, with where its value comes from.

use crate::engine;
use crate::manager::Manager;
use crate::registry::{Tree, Value};
use crate::ui::{h, locked, phead, ppath, svg, values, LOCKED};
use crate::vocab::{self, Shape, BUNDLES, SETTINGS};

/// Every profile, parents first, as (path, depth, key).
pub fn nodes(root: Option<&Tree>) -> Vec<(String, usize, &Tree)> {
    fn go<'a>(list: &'a [Tree], base: &str, depth: usize, out: &mut Vec<(String, usize, &'a Tree)>) {
        for t in list {
            let path = if base.is_empty() { t.name.clone() } else { format!("{base}/{}", t.name) };
            out.push((path.clone(), depth, t));
            go(&t.children, &path, depth + 1, out);
        }
    }
    let mut out = Vec::new();
    if let Some(root) = root {
        go(&root.children, "", 0, &mut out);
    }
    out
}

/// The profiles from the top down to `path`, each with its own values.
fn chain<'a>(root: &'a Tree, path: &str) -> Vec<(String, &'a Tree)> {
    let mut out = Vec::new();
    let mut here = root;
    let mut walked = String::new();
    for part in path.split('/') {
        let Some(next) = here.child(part) else { break };
        walked = if walked.is_empty() { next.name.clone() } else { format!("{walked}/{}", next.name) };
        out.push((walked.clone(), next));
        here = next;
    }
    out
}

fn shown(setting: &vocab::Setting, value: &Value) -> String {
    match (setting.shape, value) {
        (Shape::Switch, v) => if v.as_int() == Some(0) { "Off" } else { "On" }.into(),
        (Shape::Tri, v) => if v.as_int() == Some(0) { "No" } else { "Yes" }.into(),
        (Shape::List, v) => {
            let list = v.as_list().unwrap_or_default();
            if list.iter().all(|s| s.is_empty()) { "None".into() } else { list.join(", ") }
        }
        (_, v) => v.text(),
    }
}

fn has(v: Option<&Value>) -> bool {
    match v {
        Some(Value::List(l)) => l.iter().any(|s| !s.is_empty()),
        Some(Value::Str(s)) => !s.is_empty(),
        Some(_) => true,
        None => false,
    }
}

fn on(v: Option<&Value>) -> bool {
    v.and_then(Value::as_int).is_some_and(|i| i != 0)
}

pub fn page(m: &Manager) -> String {
    let may = m.config.may.profiles && m.busy.is_none();
    let profiles = m.profiles_with_draft();
    let all = nodes(m.config.profiles());
    if all.is_empty() {
        return format!(
            "{}{}<div class=\"panel pad\"><p class=\"empty-note\">No profiles yet. A profile says how an interface stands on a network.</p>{}</div>",
            phead("Profiles", "", ""),
            locked(may, LOCKED),
            tree_actions(may, None)
        );
    }
    let path = m.profile.clone().unwrap_or_else(|| all[0].0.clone());
    let root = profiles.as_ref().expect("there are profiles");
    let chain = chain(root, &path);
    let users = |p: &str| m.state.interfaces.iter().filter(|i| i.status.profile.as_deref().is_some_and(|q| q.eq_ignore_ascii_case(p))).map(|i| i.name().to_string()).collect::<Vec<_>>();
    let tree: String = all
        .iter()
        .map(|(p, d, t)| {
            let uses: String = users(p).iter().map(|u| format!("<span>{}</span>", h(u))).collect();
            let disabled = t.value("Enabled").and_then(Value::as_int) == Some(0);
            format!(
                r#"<button class="{}" fx-click="profile-select"{}{}>{}<span class="nm">{}</span>{}<span class="uses">{uses}</span></button>"#,
                crate::ui::depth(*d),
                values(&[("p", p)]),
                if *p == path { r#" aria-current="true""# } else { "" },
                if *d > 0 { r#"<span class="elbow"></span>"# } else { "" },
                h(&t.name),
                if disabled { r#" <span class="tag">Off</span>"# } else { "" }
            )
        })
        .collect();
    // Each setting's effective value, and the profile it comes from.
    let effective = |key: &str| chain.iter().rev().find_map(|(p, t)| t.value(key).map(|v| (v.clone(), p.clone())));
    let saved = m.config.profiles().and_then(|t| t.at(&path)).map(|t| t.values.clone()).unwrap_or_default();
    let draft = m.draft.as_ref().filter(|d| d.path == path);
    let changed: Vec<String> = match draft {
        None => Vec::new(),
        Some(d) => SETTINGS
            .iter()
            .map(|s| s.key())
            .filter(|k| saved.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v) != d.get(k))
            .collect(),
    };
    let inherit = if chain.len() > 1 { "Inherit" } else { "Default" };
    let undo = svg("undo").replace("class=\"ico\"", "");
    let control = |s: &vocab::Setting, v: Option<&Value>| -> String {
        let key = s.key();
        let off = if may { "" } else { " disabled" };
        let seg = |words: [&str; 2]| {
            let b = |val: &str, label: &str, pressed: bool, class: &str| format!(r#"<button class="{class}" fx-click="pv-set"{} aria-pressed="{pressed}"{off}>{label}</button>"#, values(&[("k", &key), ("v", val)]));
            format!(
                r#"<span class="seg sm" role="group" aria-label="{}">{}{}{}</span>"#,
                h(s.label),
                b("", inherit, v.is_none(), "inherit"),
                b("1", words[0], v.is_some() && on(v), ""),
                b("0", words[1], v.is_some() && !on(v), "")
            )
        };
        let clear = if v.is_some() && may { format!(r#"<button class="undo" fx-click="pv-clear"{} title="{inherit} instead" aria-label="{inherit} instead">{undo}</button>"#, values(&[("k", &key)])) } else { String::new() };
        match s.shape {
            Shape::Switch => seg(["On", "Off"]),
            Shape::Tri => seg(["Yes", "No"]),
            Shape::Number => format!(r#"<input class="inp short mono" name="pv:{key}" placeholder="{inherit}" inputmode="numeric"{off}>{clear}"#),
            Shape::Choice(words) => {
                let opts: String = std::iter::once(format!(r#"<option value="">{inherit}</option>"#)).chain(words.iter().map(|w| format!(r#"<option value="{w}">{w}</option>"#))).collect();
                format!(r#"<select class="sel" name="pv:{key}"{off}>{opts}</select>{clear}"#)
            }
            Shape::List => {
                let list = v.and_then(Value::as_list).unwrap_or_default();
                let chips: String = list
                    .iter()
                    .filter(|x| !x.is_empty())
                    .enumerate()
                    .map(|(i, x)| format!(r#"<span class="chip">{}{}</span>"#, h(x), if may { format!(r#"<button fx-click="pv-del"{} aria-label="Remove {}">×</button>"#, values(&[("k", &key), ("i", &i.to_string())]), h(x)) } else { String::new() }))
                    .collect();
                let none = if v.is_some() && list.iter().all(|x| x.is_empty()) { r#"<span class="chip">None</span>"# } else { "" };
                let placeholder = if v.is_none() { inherit.to_string() } else { format!("Add, e.g. {}", s.example) };
                format!(
                    r#"<span class="chiplist">{chips}{none}<form fx-submit="pv-add"{} class="inline-form"><input class="inp mono w130" name="pa:{key}" placeholder="{}" autocomplete="off"{off}></form>{clear}</span>"#,
                    values(&[("k", &key)]),
                    h(&placeholder)
                )
            }
        }
    };
    let cols = chain.len();
    let mut rows = String::new();
    for (bundle, title) in BUNDLES {
        rows += &format!(r#"<tr><td class="grp" colspan="{}">{}</td></tr>"#, cols + 2, h(title));
        for s in SETTINGS.iter().filter(|s| s.bundle == *bundle) {
            let key = s.key();
            let winner = effective(&key).map(|(_, p)| p);
            let mut row = format!(r#"<tr><td>{}{}</td>"#, h(s.label), if changed.contains(&key) { r#" <span class="chg" title="Not applied"></span>"# } else { "" });
            for (i, (p, t)) in chain.iter().enumerate() {
                if i + 1 == cols {
                    row += &format!(r#"<td><div class="ctl">{}</div></td>"#, control(s, t.value(&key)));
                } else {
                    row += &match t.value(&key) {
                        Some(v) => format!(r#"<td><span class="val{}">{}</span></td>"#, if winner.as_deref() != Some(p.as_str()) { " over" } else { "" }, h(&shown(s, v))),
                        None => r#"<td><span class="unset">—</span></td>"#.into(),
                    };
                }
            }
            row += &match effective(&key) {
                Some((v, from)) => format!(r#"<td class="eff"><span class="val">{}</span>{}</td>"#, h(&shown(s, &v)), if from != path { format!(r#"<span class="src">from {}</span>"#, ppath(&from)) } else { String::new() }),
                None => format!(r#"<td class="eff"><span class="unset">{}</span><span class="src">built in</span></td>"#, h(s.default)),
            };
            rows += &row;
            rows += "</tr>";
        }
    }
    let ev = |k: &str| effective(k).map(|(v, _)| v);
    let pick = |auto: bool, set: bool, words: [&str; 4]| -> (String, &'static str) {
        match (auto, set) {
            (true, true) => (words[2].into(), "both"),
            (true, false) => (words[0].into(), "auto"),
            (false, true) => (words[1].into(), "man"),
            (false, false) => (words[3].into(), ""),
        }
    };
    let mtu = ev("Mtu.Value").map(|v| v.text()).unwrap_or_default();
    let bundles = [
        ("Addressing", pick(on(ev("Address.Offered").as_ref()), has(ev("Address.Static").as_ref()), ["Automatic", "Static", "Both", "None"])),
        ("Gateway", pick(on(ev("Route.Offered").as_ref()), has(ev("Route.Gateway").as_ref()), ["Automatic", "Static", "Both", "None"])),
        ("DNS", pick(on(ev("Dns.Offered").as_ref()), has(ev("Dns.Servers").as_ref()), ["Automatic", "Manual", "Both", "None"])),
        ("Hostname", pick(on(ev("Hostname.Offered").as_ref()), on(ev("Hostname.Announce").as_ref()), ["Accept", "Announce", "Both", "Off"])),
        ("MTU", pick(on(ev("Mtu.Offered").as_ref()), !mtu.is_empty(), ["Automatic", &mtu, "Both", "Unchanged"])),
    ]
    .iter()
    .map(|(k, (v, class))| format!(r#"<div><span class="k">{k}</span><span class="v {class}" title="{}">{}</span></div>"#, h(v), h(v)))
    .collect::<String>();
    let head: String = chain.iter().enumerate().map(|(i, (p, t))| format!(r#"<th class="pc{}" title="{} {}">{}</th>"#, if i + 1 == cols { " cur" } else { "" }, if i + 1 == cols { "Editing" } else { "Inherited from" }, h(p), h(&t.name))).collect();
    let used = users(&path);
    let pending = if changed.is_empty() {
        String::new()
    } else {
        let mut policy = m.config.policy.clone();
        policy.profiles = profiles.clone();
        let report = engine::check(&policy, &m.subjects());
        let problem = report.refusals.first().map(|r| format!(r#"<small class="bad-text">{}</small>"#, h(r))).unwrap_or_else(|| {
            format!("<small>{}</small>", if used.is_empty() { "No interface uses this profile.".to_string() } else { format!("Applies to {} at once.", used.join(", ")) })
        });
        format!(
            r#"<div class="pending"><div class="grow"><b>{} change{} not applied</b>{problem}</div><button class="btn" fx-click="profile-discard">Discard</button><button class="btn primary" fx-click="profile-apply"{}>Apply</button></div>"#,
            changed.len(),
            if changed.len() == 1 { "" } else { "s" },
            if may && report.ok() { "" } else { " disabled" }
        )
    };
    format!(
        r#"{}{}<div class="split"><div><div class="ptree">{tree}</div>{}</div><div class="minw0"><div class="chosen"><b>{}</b><span class="muted">{}</span></div><div class="bundles">{bundles}</div><div class="bundlekey"><span><i class="warn"></i>From the network</span><span><i class="good"></i>Set here</span><span><i class="accent"></i>Both</span></div><div class="panel scroll"><table class="tbl cascade"><thead><tr><th class="set">Setting</th>{head}<th class="eff">Result</th></tr></thead><tbody>{rows}</tbody></table></div></div></div>{pending}"#,
        phead("Profiles", "How an interface is set up on a network. A profile inside another inherits every setting from it and changes only what it sets.", ""),
        locked(m.config.may.profiles, LOCKED),
        tree_actions(may, Some(&path)),
        ppath(&path),
        h(&if used.is_empty() { "Not in use".to_string() } else { format!("Used by {}", used.join(", ")) })
    )
}

fn tree_actions(may: bool, selected: Option<&str>) -> String {
    let off = if may { "" } else { " disabled" };
    let name = selected.map(|p| p.rsplit('/').next().unwrap_or(p)).unwrap_or_default();
    let inside = if selected.is_some() { format!(r#"<button class="btn sm" fx-click="profile-new"{}{off}>{}Inside {}</button>"#, values(&[("where", "inside")]), svg("plus"), h(name)) } else { String::new() };
    let delete = if selected.is_some() { format!(r#"<button class="btn sm danger" fx-click="profile-delete"{off}>Delete {}</button>"#, h(name)) } else { String::new() };
    format!(
        r#"<div class="treeacts"><input class="inp" name="np-name" placeholder="New profile's name" autocomplete="off"{off}><button class="btn sm" fx-click="profile-new"{}{off}>{}New profile</button>{inside}{delete}</div>"#,
        values(&[("where", "top")]),
        svg("plus")
    )
}
