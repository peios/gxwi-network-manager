//! A rule being written: what it matches, what it does, where it sits, and
//! what saving it would change, checked by the machine's laws as it is
//! written.

use crate::engine::{self, Policy};
use crate::manager::{Col, Manager, RuleDraft};
use crate::pages::firewall::{self, built_in};
use crate::pages::profiles;
use crate::rules::{self, Cond, Layer, Verdict};
use crate::ui::{actions, h, ppath, svg, values};
use crate::vocab::{self, Suggest, FACTS};

/// The words a value's field suggests.
fn suggestions(m: &Manager, suggest: Suggest) -> Vec<String> {
    match suggest {
        Suggest::None => Vec::new(),
        Suggest::Words(words) => words.iter().map(|w| w.to_string()).collect(),
        Suggest::Interfaces => m.state.interfaces.iter().map(|i| i.name().to_string()).chain(std::iter::once("lo".to_string())).collect(),
        Suggest::InterfaceIds => m.state.interfaces.iter().map(|i| i.status.ifid.clone()).collect(),
        Suggest::NetworkNames => m.config.networks.iter().filter_map(|n| n.name.clone()).collect(),
        Suggest::NetworkIds => m.config.networks.iter().map(|n| n.id.clone()).collect(),
        Suggest::Services => ["sshd", "gxwid", "resolvd", "netd", "timed", "peipkg", "pnpd"].iter().map(|s| s.to_string()).collect(),
        Suggest::Trust => vocab::TRUST.iter().map(|(v, _, _)| v.to_string()).collect(),
        Suggest::Principals => ["SYSTEM", "LocalService", "NetworkService", "Administrators", "Users", "Everyone"].iter().map(|s| s.to_string()).collect(),
    }
}

/// What is wrong with a condition, as far as can be said of it alone.
fn own_problem(c: &Cond, layer: Layer) -> Option<String> {
    let Some(fact) = vocab::lookup(&c.fact) else { return Some("PNP has no such fact.".into()) };
    if fact.layers & layer.bit() == 0 {
        return Some(format!("{} never exists in {}, so this can never match.", c.fact, layer.title().to_lowercase()));
    }
    if c.op != "Present" && c.items.iter().all(|i| i.trim().is_empty()) {
        return Some("Enter a value.".into());
    }
    None
}

fn condition(m: &Manager, d: &RuleDraft, i: usize, c: &Cond, problem: Option<&str>) -> String {
    let may = m.may_rules();
    let off = if may { "" } else { " disabled" };
    let layer = d.layer;
    let prefixed = c.fact.starts_with("Tag.") || c.fact.starts_with("Counter.");
    let fact = if prefixed {
        format!(r#"<input class="inp mono" name="cf{i}" title="The fact, with its name"{off}>"#)
    } else {
        let mut groups: Vec<&str> = Vec::new();
        for f in FACTS.iter().filter(|f| f.layers & layer.bit() != 0 || f.name == c.fact) {
            if !groups.contains(&f.group) {
                groups.push(f.group);
            }
        }
        let opts: String = groups
            .iter()
            .map(|g| {
                let inner: String = FACTS
                    .iter()
                    .filter(|f| f.group == *g && (f.layers & layer.bit() != 0 || f.name == c.fact))
                    .map(|f| format!(r#"<option value="{}" title="{}">{}</option>"#, h(f.name), h(f.about), h(&if f.name.ends_with('.') { format!("{}…", f.name) } else { f.name.to_string() })))
                    .collect();
                format!(r#"<optgroup label="{}">{inner}</optgroup>"#, h(g))
            })
            .collect();
        format!(r#"<select class="sel" name="cf{i}"{off}>{opts}</select>"#)
    };
    let family = vocab::lookup(&c.fact).map(|f| f.family).unwrap_or(vocab::Family::Str);
    let ops: String = vocab::operators(family).iter().map(|o| format!(r#"<option value="{o}">{}</option>"#, vocab::operator_words(o))).collect();
    let op = format!(r#"<select class="sel" name="co{i}"{off}>{ops}</select>"#);
    let value = if c.op == "Present" {
        format!(r#"<select class="sel" name="cv{i}"{off}><option value="1">yes</option><option value="0">no</option></select>"#)
    } else {
        let list = vocab::lookup(&c.fact).map(|f| suggestions(m, f.suggest)).unwrap_or_default();
        let datalist = if list.is_empty() { String::new() } else { format!(r#"<datalist id="cl{i}">{}</datalist>"#, list.iter().map(|v| format!(r#"<option value="{}">"#, h(v))).collect::<String>()) };
        let hint = match family {
            vocab::Family::Int => "22, or 1024-65535",
            vocab::Family::Addr => "10.0.0.0/8",
            vocab::Family::Mac => "aa:bb:cc:dd:ee:ff",
            _ => "",
        };
        format!(r#"<input class="inp mono" name="cv{i}" placeholder="{hint}" autocomplete="off"{}{off}>{datalist}"#, if list.is_empty() { String::new() } else { format!(r#" list="cl{i}""#) })
    };
    let err = problem.map(|p| format!(r#"<div class="err">{}</div>"#, h(p))).unwrap_or_default();
    format!(r#"<div class="cond">{fact}{op}{value}<button class="x" fx-click="cond-del"{}{off} aria-label="Remove this condition">×</button>{err}</div>"#, values(&[("i", &i.to_string())]))
}

fn action_ui(m: &Manager, d: &RuleDraft) -> String {
    let may = m.may_rules();
    let off = if may { "" } else { " disabled" };
    let verdict = d.rule.verdict().and_then(rules::verdict_of);
    let interface = d.layer == Layer::Interface;
    let current = match &verdict {
        Some(Verdict::Join(_)) => "JOIN",
        Some(Verdict::Ignore) => "IGNORE",
        Some(Verdict::Down) => "DOWN",
        Some(Verdict::Allow) => "PASS",
        Some(Verdict::Block) => "DROP",
        Some(Verdict::Reject { .. }) => "REJECT",
        None => "",
    };
    let choices: &[(&str, &str)] = if interface { &[("JOIN", "Use profile"), ("IGNORE", "Unmanaged"), ("DOWN", "Disabled"), ("", "None")] } else { &[("PASS", "Allow"), ("DROP", "Block"), ("REJECT", "Reject"), ("", "None")] };
    let seg: String = choices.iter().map(|(v, l)| format!(r#"<button fx-click="rv"{} aria-pressed="{}"{off}>{l}</button>"#, values(&[("v", v)]), *v == current)).collect();
    let extra = match &verdict {
        Some(Verdict::Reject { .. }) => format!(r#"<select class="sel" name="r-rej" aria-label="Reply"{off}><option value="Refused">Reply: connection refused</option><option value="Prohibited">Reply: administratively prohibited</option></select>"#),
        Some(Verdict::Join(_)) => {
            let opts: String = profiles::nodes(m.config.profiles()).iter().map(|(p, _, _)| format!(r#"<option value="{}">{}</option>"#, h(p), ppath(p))).collect();
            format!(r#"<select class="sel" name="r-prof" aria-label="Profile"{off}>{opts}</select>"#)
        }
        _ => String::new(),
    };
    let help = match current {
        "JOIN" => "Bring the interface up and set it up with a profile.",
        "IGNORE" => "Leave the interface exactly as it is.",
        "DOWN" => "Keep the interface switched off.",
        "PASS" => "Let it through.",
        "DROP" => "Discard it without a reply. The sender sees a timeout.",
        "REJECT" => "Refuse it and tell the sender.",
        _ => "Decide nothing. The rule's other actions still run, and the rule it is inside decides.",
    };
    format!(r#"<div class="actseg"><span class="seg" role="group" aria-label="Action">{seg}</span>{extra}</div><div class="acthelp">{help}</div>"#)
}

/// What saving would change: interfaces' profiles, or which services are
/// reachable from where; and whether it cuts the person off.
fn impact(m: &Manager, d: &RuleDraft, policy: &Policy) -> String {
    let mut rows = String::new();
    if d.layer == Layer::Interface {
        let (Ok(before), Ok(after)) = (engine::interface_policy(&m.config.policy), engine::interface_policy(policy)) else { return String::new() };
        let words = |v: &Verdict| match v {
            Verdict::Join(p) => ppath(p),
            other => h(other.result()),
        };
        for i in &m.state.interfaces {
            let subject = i.subject(&m.config);
            let (was, _, _) = engine::judge_interface(&before, &subject);
            let (will, _, tie) = engine::judge_interface(&after, &subject);
            if tie {
                rows += &format!(r#"<div class="ir cut"><span class="grow">{}</span><span>Conflicts with another rule at the same priority</span></div>"#, h(i.name()));
            } else if was != will {
                rows += &format!(r#"<div class="ir"><span class="grow">{}</span><span>{} <span class="arrowtxt">→</span> <b>{}</b></span></div>"#, h(i.name()), words(&was), words(&will));
            }
        }
        if rows.is_empty() {
            rows = r#"<div class="none">No interface changes.</div>"#.into();
        }
        return format!(r#"<div class="impact"><div class="ih">What this changes</div>{rows}</div>"#);
    }
    let before = firewall::exposure(m, &m.config.policy);
    let after = firewall::exposure(m, policy);
    for (a, b) in before.iter().zip(&after) {
        for col in [Col::Private, Col::Public] {
            let (Some(x), Some(y)) = (a.cells.iter().find(|c| c.col == col), b.cells.iter().find(|c| c.col == col)) else { continue };
            if x.state != y.state {
                let word = |s: firewall::State| match s {
                    firewall::State::Allow => "Allowed",
                    firewall::State::Limited => "Limited",
                    firewall::State::Block => "Blocked",
                    firewall::State::NotListening => "Not listening",
                };
                rows += &format!(r#"<div class="ir"><span class="grow">{} · {}</span><span>{} <span class="arrowtxt">→</span> <b>{}</b></span></div>"#, h(&b.title), firewall::col_title(col), word(x.state), word(y.state));
            }
        }
    }
    let cut = m.cut(policy, None);
    let cut: String = cut.iter().map(|c| format!(r#"<div class="ir cut"><span class="grow">Your session: {}</span><b>Blocked</b></div>"#, h(c))).collect();
    if rows.is_empty() && cut.is_empty() {
        rows = r#"<div class="none">No change to what listening services can be reached from.</div>"#.into();
    }
    format!(r#"<div class="impact"><div class="ih">What this changes</div>{cut}{rows}</div>"#)
}

pub fn drawer(m: &Manager, d: &RuleDraft) -> String {
    let may = m.may_rules();
    let off = if may { "" } else { " disabled" };
    let layer = d.layer;
    let interface = layer == Layer::Interface;
    let forest = m.config.policy.forest(layer);
    let target = d.target();
    let named = rules::check_name(&d.rule.name).err();
    let taken = d.path.is_none() && named.is_none() && rules::find(forest, &target).is_some();
    let policy = d.applied(&m.config.policy);
    let report = engine::check(&policy, &m.subjects());
    // The machine's reasons that are this rule's, by the condition they
    // name; the rest are the rule's own.
    let mine = format!("Rule {target}:");
    let mut theirs: Vec<String> = Vec::new();
    let mut problems: Vec<Option<String>> = d.rule.conds.iter().map(|c| own_problem(c, layer)).collect();
    for r in &report.refusals {
        match d.rule.conds.iter().position(|c| r.starts_with(&mine) && r.contains(&c.key())) {
            Some(i) if problems[i].is_none() => problems[i] = Some(r.trim_start_matches(&mine).trim().to_string()),
            Some(_) => {}
            None => theirs.push(r.clone()),
        }
    }
    let conds: String = d.rule.conds.iter().enumerate().map(|(i, c)| condition(m, d, i, c, problems[i].as_deref())).collect();
    let refused = !report.ok() || named.is_some() || taken;
    let parent = d.parent.as_deref().and_then(|p| rules::find(forest, p));
    let context = match (&d.parent, parent) {
        (Some(path), Some(parent)) => {
            let mut chain = Vec::new();
            let mut walked = String::new();
            for part in path.split('/') {
                walked = if walked.is_empty() { part.to_string() } else { format!("{walked}/{part}") };
                if let Some(r) = rules::find(forest, &walked) {
                    chain.push(rules::summary(&r.conds, layer));
                }
            }
            format!(
                r#"<div class="ctx"><span class="k">Exception to {}</span><span class="s">{} <span class="arrowtxt">→</span> {}</span><p>This rule applies only to {} that {} already matches. Where both match, this rule's action is used instead.</p></div>"#,
                ppath(path),
                h(&chain.join(" · ")),
                actions(&parent.actions, layer),
                if interface { "interfaces" } else { "traffic" },
                h(&parent.name)
            )
        }
        _ => String::new(),
    };
    let kept: Vec<Cond> = d.rule.conds.iter().zip(&problems).filter(|(_, p)| p.is_none()).map(|(c, _)| c.clone()).collect();
    let sumline = format!(r#"<div class="sumline">{} <span class="arrowtxt">→</span> {}</div>"#, h(&rules::summary(&kept, layer)), actions(&d.rule.actions, layer));
    let effects: Vec<&str> = d.rule.effects();
    let also = {
        let list: String = effects.iter().enumerate().map(|(i, _)| format!(r#"<div class="e"><input class="inp mono" name="fx{i}" autocomplete="off"{off}><button class="x" fx-click="fx-del"{}{off} aria-label="Remove">×</button></div>"#, values(&[("i", &i.to_string())]))).collect();
        let adds: &[(&str, &str)] = if interface { &[("Audit", "REPORT(3)")] } else { &[("Count", "COUNT(name)"), ("Tag", "TAG(name, Set)"), ("Audit", "REPORT(3)"), ("Prompt", "PROMPT(handler, DROP)")] };
        let buttons: String = adds.iter().map(|(l, e)| format!(r#"<button class="btn sm" fx-click="fx-add"{}{off}>{l}</button>"#, values(&[("e", e)]))).collect();
        format!(r#"<div class="minihead gap">Also</div><div class="effects">{list}<div class="buttons">{buttons}</div></div>"#)
    };
    let kids = match &d.path {
        Some(path) => {
            let children = rules::find(forest, path).map(|r| r.children.clone()).unwrap_or_default();
            let list: String = if children.is_empty() {
                format!(r#"<div class="none">None. Add one to carve out {} this rule should treat differently.</div>"#, if interface { "interfaces" } else { "traffic" })
            } else {
                children
                    .iter()
                    .map(|k| format!(r#"<button class="kid" fx-click="rule-open"{}><span class="grow"><b>{}</b><small>{}</small></span>{}</button>"#, values(&[("layer", layer.key()), ("p", &format!("{path}/{}", k.name))]), h(&k.name), h(&rules::summary(&k.conds, layer)), actions(&k.actions, layer)))
                    .collect()
            };
            format!(r#"<div class="minihead gap">Exceptions</div><div class="kids">{list}</div><div class="gap-top8"><button class="btn sm" fx-click="rule-child"{off}>{}Add exception</button></div>"#, svg("plus"))
        }
        None => String::new(),
    };
    let elsewhere = if theirs.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="problems"><b>The machine would refuse this:</b>{}</div>"#, theirs.iter().map(|t| format!("<span>{}</span>", h(t))).collect::<String>())
    };
    let lints: Vec<&String> = report.lints.iter().filter(|l| l.starts_with(&mine)).collect();
    let lints = if lints.is_empty() { String::new() } else { format!(r#"<div class="problems lint">{}</div>"#, lints.iter().map(|l| format!("<span>{}</span>", h(l))).collect::<String>()) };
    let body = format!(
        r#"{context}{sumline}<div class="fgrid"><label class="fld"><span>Name</span><input class="inp mono" name="r-name" autocomplete="off" spellcheck="false"{}{}></label><label class="fld"><span>Priority</span><input class="inp" name="r-prio" placeholder="{}" inputmode="numeric"{off}></label><label class="fld left"><span>On</span><input type="checkbox" class="sw" name="r-on"{off}></label></div><div class="minihead gap">{}</div>{conds}<button class="btn sm" fx-click="cond-add"{off}>{}Add condition</button><div class="minihead gap">Action</div>{}{also}{elsewhere}{lints}{}{kids}"#,
        if d.path.is_some() { " disabled" } else { off },
        if d.path.is_none() { " fx-autofocus" } else { "" },
        if d.parent.is_some() { "Inherit" } else { "0" },
        if d.parent.is_some() { "And also matches" } else { "Matches" },
        svg("plus"),
        action_ui(m, d),
        if refused { String::new() } else { impact(m, d, &policy) }
    );
    let status = match (&named, taken) {
        (Some(why), _) => why.clone(),
        (None, true) => format!("There is already a rule called {target}."),
        _ if refused => "Fix what is marked first.".into(),
        _ => String::new(),
    };
    let existing = d.path.is_some();
    let foot = format!(
        r#"{}{}<span class="grow{}">{}</span><button class="btn" fx-click="close">Cancel</button><button class="btn primary" fx-click="rule-save"{}>Save</button>"#,
        if existing { format!(r#"<button class="btn danger" fx-click="rule-delete"{off}>Delete</button>"#) } else { String::new() },
        if existing && !interface { r#"<button class="btn" fx-click="rule-test">Test</button>"# } else { "" },
        if refused && !status.is_empty() { " bad" } else { "" },
        h(&status),
        if refused || !may { " disabled" } else { "" }
    );
    let title = match (&d.path, &d.parent) {
        (Some(p), _) => {
            let name = p.rsplit('/').next().unwrap_or(p);
            if built_in(layer, p) { format!("{name} (built in)") } else { name.to_string() }
        }
        (None, Some(parent)) => format!("New exception to {}", parent.rsplit('/').next().unwrap_or(parent)),
        (None, None) => if interface { "New profile rule".into() } else { format!("New rule: {}", layer.title().to_lowercase()) },
    };
    super::drawer(&title, &body, &foot)
}
