//! The window: its sections, what is open in them, and every change.
//!
//! What is shown is read on threads (`machine`, `live`) and lands here.
//! What is changed goes one way, [`Manager::propose`]: the change is built
//! as registry edits with the edits that would undo it; checked by the
//! machine's own laws (`engine::check`) and refused here if the machine
//! would refuse it; checked against this desktop's own connections, which
//! the person is asked about before it can cut them; then written as one
//! transaction. A change that could cut the person off is kept only once
//! they say so: unconfirmed, it is undone after thirty seconds.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Weak;
use std::time::{Duration, Instant};

use libgxwi::{Facts, Fields, Live as Surfaced, Surface, Value};

use crate::engine::{self, Conn, Context, Judge, Policy};
use crate::live::{self, Live};
use crate::machine::{self, Config, State};
use crate::registry::{Batch, Edit, Tree, Value as RegValue};
use crate::rules::{self, Cond, Layer, Rule, Verdict};
use crate::{pages, ui};

/// How long a risky change waits to be kept.
pub const KEEP: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Overview,
    Networks,
    Profiles,
    Assign,
    Dns,
    Exposure,
    Rules,
    Activity,
    Ports,
    Audit,
    Advanced,
}

impl View {
    pub const ALL: [View; 11] = [View::Overview, View::Networks, View::Profiles, View::Assign, View::Dns, View::Exposure, View::Rules, View::Activity, View::Ports, View::Audit, View::Advanced];

    pub fn id(self) -> &'static str {
        match self {
            View::Overview => "overview",
            View::Networks => "networks",
            View::Profiles => "profiles",
            View::Assign => "assign",
            View::Dns => "dns",
            View::Exposure => "exposure",
            View::Rules => "rules",
            View::Activity => "activity",
            View::Ports => "ports",
            View::Audit => "audit",
            View::Advanced => "advanced",
        }
    }

    pub fn by(id: &str) -> Option<View> {
        View::ALL.into_iter().find(|v| v.id() == id)
    }
}

/// Which networks a cell of the exposure matrix is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Col {
    Private,
    Public,
    Local,
}

impl Col {
    pub fn id(self) -> &'static str {
        match self {
            Col::Private => "private",
            Col::Public => "public",
            Col::Local => "local",
        }
    }

    pub fn by(id: &str) -> Option<Col> {
        [Col::Private, Col::Public, Col::Local].into_iter().find(|c| c.id() == id)
    }
}

/// A rule being written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleDraft {
    pub layer: Layer,
    /// The rule's path when it exists already.
    pub path: Option<String>,
    /// The rule it is an exception to.
    pub parent: Option<String>,
    pub rule: Rule,
}

impl RuleDraft {
    /// Where it is, or will be.
    pub fn target(&self) -> String {
        match (&self.path, &self.parent) {
            (Some(p), _) => p.clone(),
            (None, Some(parent)) => format!("{parent}/{}", self.rule.name.trim()),
            (None, None) => self.rule.name.trim().to_string(),
        }
    }

    /// The policy as it would be with this rule saved.
    pub fn applied(&self, policy: &Policy) -> Policy {
        let mut out = policy.clone();
        let mut rule = self.rule.clone();
        rule.name = rule.name.trim().to_string();
        rules::put(out.forest_mut(self.layer), &self.target(), rule);
        out
    }
}

/// A connection being explained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trace {
    pub conn: Conn,
    /// The person describes it.
    pub edit: bool,
    /// The exposure cell it came from: its row and column.
    pub cell: Option<(usize, Col)>,
    /// The layer whose rules are shown; the deciding one when `None`.
    pub layer: Option<Layer>,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drawer {
    Network { id: String },
    Rule(RuleDraft),
    Trace(Trace),
}

/// A change, ready to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// What it does, said when it is done: "Rule ssh saved".
    pub what: String,
    pub batch: Batch,
    pub undo: Batch,
    /// It could cut the person off: it is kept only when they say so.
    pub risky: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modal {
    /// The change would cut these connections to the desktop.
    Cutoff { pending: Pending, cut: Vec<String> },
    /// Delete this rule and its exceptions?
    DeleteRule { layer: Layer, path: String, exceptions: usize },
    DeleteProfile { path: String },
}

/// A risky change made, waiting to be kept.
#[derive(Debug, Clone)]
pub struct Keep {
    pub what: String,
    pub undo: Batch,
    pub until: Instant,
    pub number: u64,
}

/// A profile being edited: its own values as they would be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileDraft {
    pub path: String,
    pub values: Vec<(String, RegValue)>,
}

impl ProfileDraft {
    pub fn get(&self, key: &str) -> Option<&RegValue> {
        self.values.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v)
    }

    pub fn set(&mut self, key: &str, value: Option<RegValue>) {
        let at = self.values.iter().position(|(k, _)| k.eq_ignore_ascii_case(key));
        match (at, value) {
            (Some(i), Some(v)) => self.values[i].1 = v,
            (None, Some(v)) => self.values.push((key.to_string(), v)),
            (Some(i), None) => {
                self.values.remove(i);
            }
            (None, None) => {}
        }
    }
}

/// A network's id, and its name, trust and preferred address as edited.
pub type NetworkEdit = (String, Option<String>, Option<String>, Option<String>);

/// A name looked up.
#[derive(Debug, Clone, Default)]
pub struct Lookup {
    pub name: String,
    pub aaaa: bool,
    pub answer: Option<Result<libresolv::Answer, String>>,
    pub asking: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortCheck {
    pub port: String,
    pub protocol: String,
    pub who: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Connections,
    Counters,
}

pub struct Manager {
    pub window: Weak<Surface<Manager>>,
    pub view: View,
    pub config: Config,
    pub state: State,
    pub live: Live,
    /// Read at least once.
    pub read: bool,
    /// Each interface's received and sent bytes a second, newest last.
    pub traffic: BTreeMap<String, VecDeque<(f64, f64)>>,
    counted: BTreeMap<String, (u64, u64, Instant)>,
    /// The interface open on the overview.
    pub selected: Option<String>,
    pub layer: Layer,
    pub tab: Tab,
    pub profile: Option<String>,
    pub draft: Option<ProfileDraft>,
    pub drawer: Option<Drawer>,
    pub modal: Option<Modal>,
    pub keep: Option<Keep>,
    keeps: u64,
    pub lookup: Lookup,
    pub port_check: Option<PortCheck>,
    pub said: Option<Result<String, String>>,
    /// What is being written now.
    pub busy: Option<String>,
    /// The engine's generation, as the live state reports it.
    pub generation: u64,
    pub renewing: Option<String>,
    /// The permissions editor is open.
    pub editing: bool,
}

fn named(value: &Value, key: &str) -> String {
    value.get(key).and_then(Value::as_str).unwrap_or_default().to_string()
}

impl Manager {
    pub fn new() -> Manager {
        Manager {
            window: Weak::new(),
            view: View::Overview,
            config: Config::default(),
            state: State::default(),
            live: live::read(&Config::default(), &State::default(), 42),
            read: false,
            traffic: BTreeMap::new(),
            counted: BTreeMap::new(),
            selected: None,
            layer: Layer::Flow,
            tab: Tab::Connections,
            profile: None,
            draft: None,
            drawer: None,
            modal: None,
            keep: None,
            keeps: 0,
            lookup: Lookup { name: "peios.org".into(), ..Lookup::default() },
            port_check: None,
            said: None,
            busy: None,
            generation: 42,
            renewing: None,
            editing: false,
        }
    }

    // ---- reading -------------------------------------------------------

    /// Reads the configuration again, on a thread.
    pub fn reread(&self) {
        let window = self.window.clone();
        std::thread::spawn(move || {
            let config = machine::read_config();
            if let Some(window) = window.upgrade() {
                window.update(|m, fields| m.heard_config(config, fields));
            }
        });
    }

    fn heard_config(&mut self, config: Config, fields: &mut Fields) {
        self.config = config;
        if self.profile.as_deref().is_none_or(|p| self.config.profiles().and_then(|t| t.at(p)).is_none()) {
            self.profile = self.config.profiles().and_then(|t| t.children.first()).map(|c| c.name.clone());
            self.draft = None;
        }
        if self.draft.is_none() {
            self.start_draft(fields);
        }
        self.relive();
    }

    fn relive(&mut self) {
        self.live = live::read(&self.config, &self.state, self.generation);
    }

    /// Reads what is happening every two seconds, and the configuration
    /// whenever the registry says it changed, for as long as the window is
    /// open.
    pub fn watch(&self) {
        let window = self.window.clone();
        std::thread::spawn(move || {
            loop {
                let Some(open) = window.upgrade() else { return };
                let config = open.look(|m: &Manager, _, _| m.config.clone());
                drop(open);
                let state = machine::read_state(&config);
                let Some(open) = window.upgrade() else { return };
                open.update(|m, _| m.heard_state(state));
                drop(open);
                std::thread::sleep(Duration::from_secs(2));
            }
        });
        let window = self.window.clone();
        std::thread::spawn(move || {
            use peios::registry::{Key, KeyAccess, NotifyFilter, OpenFlags};
            let Ok(key) = Key::open(None, machine::NETWORK_KEY, KeyAccess::NOTIFY, OpenFlags::empty()) else { return };
            if key.notify(NotifyFilter::ALL, true).is_err() {
                return;
            }
            let mut buffer = vec![0u8; 16 * 1024];
            while key.read_watch_events(&mut buffer).is_ok() {
                // A change is several events: let them all land first.
                std::thread::sleep(Duration::from_millis(150));
                let Some(open) = window.upgrade() else { return };
                open.update(|m, _| m.reread());
            }
        });
    }

    fn heard_state(&mut self, state: State) {
        let now = Instant::now();
        for i in &state.interfaces {
            let name = i.name().to_string();
            if let Some((rx, tx, at)) = self.counted.get(&name) {
                let secs = now.duration_since(*at).as_secs_f64().max(0.5);
                let sample = (i.rx_bytes.saturating_sub(*rx) as f64 / secs, i.tx_bytes.saturating_sub(*tx) as f64 / secs);
                let series = self.traffic.entry(name.clone()).or_default();
                series.push_back(sample);
                while series.len() > 30 {
                    series.pop_front();
                }
            }
            self.counted.insert(name, (i.rx_bytes, i.tx_bytes, now));
        }
        if self.selected.as_deref().is_none_or(|s| state.interface(s).is_none()) {
            self.selected = state.online().or(state.interfaces.first()).map(|i| i.name().to_string());
        }
        self.state = state;
        self.read = true;
        self.relive();
    }

    // ---- who may -------------------------------------------------------

    pub fn may_rules(&self) -> bool {
        self.config.may.rules && self.busy.is_none()
    }

    pub fn subjects(&self) -> Vec<engine::Subject> {
        self.state.interfaces.iter().map(|i| i.subject(&self.config)).collect()
    }

    // ---- changing ------------------------------------------------------

    /// Connections to this desktop that `policy`, with networks as
    /// `networks` says, would refuse where they are allowed now.
    pub fn cut(&self, policy: &Policy, network: Option<(&str, Context)>) -> Vec<String> {
        let (Ok(now), Ok(then)) = (Judge::new(&self.config.policy), Judge::new(policy)) else { return Vec::new() };
        let counts = |v: &pnp_core::CounterView, c: &Conn| live::count(&self.live.counters, v, c);
        let mut out = Vec::new();
        for session in &self.state.sessions {
            let mut after = session.clone();
            if let Some((id, ctx)) = &network
                && session.network.id.as_deref() == Some(*id)
            {
                after.network = ctx.clone();
            }
            let allowed = |j: &Judge, c: &Conn| j.result(c, &counts).map(|d| d.passes()).unwrap_or(true);
            if allowed(&now, session) && !allowed(&then, &after) {
                out.push(format!("{} to port {} on {}", session.remote, session.local_port, session.interface));
            }
        }
        // An interface the desktop is reached through, no longer joined.
        if let (Ok(before), Ok(after)) = (engine::interface_policy(&self.config.policy), engine::interface_policy(policy)) {
            for session in &self.state.sessions {
                let Some(i) = self.state.interface(&session.interface) else { continue };
                let mut subject = i.subject(&self.config);
                let was = engine::judge_interface(&before, &subject).0;
                if let Some((id, ctx)) = &network
                    && subject.network.id.as_deref() == Some(*id)
                {
                    subject.network = Context { kind: subject.network.kind.clone(), ..ctx.clone() };
                }
                let will = engine::judge_interface(&after, &subject).0;
                if matches!(was, Verdict::Join(_)) && !matches!(will, Verdict::Join(_)) {
                    out.push(format!("{} to port {} ({} would stop being managed)", session.remote, session.local_port, session.interface));
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// Makes `pending`, asking first if it would cut the person off.
    pub fn propose(&mut self, pending: Pending, cut: Vec<String>) {
        if self.busy.is_some() {
            return;
        }
        if !cut.is_empty() {
            self.modal = Some(Modal::Cutoff { pending, cut });
            return;
        }
        self.commit(pending);
    }

    fn commit(&mut self, pending: Pending) {
        self.busy = Some(pending.what.clone());
        self.modal = None;
        self.said = None;
        let window = self.window.clone();
        std::thread::spawn(move || {
            let made = pending.batch.commit();
            let config = machine::read_config();
            if let Some(window) = window.upgrade() {
                window.update(|m, fields| m.committed(pending, made, config, fields));
            }
        });
    }

    fn committed(&mut self, pending: Pending, made: Result<(), String>, config: Config, fields: &mut Fields) {
        self.busy = None;
        match made {
            Ok(()) => {
                self.generation += 1;
                self.said = Some(Ok(format!("{}.", pending.what)));
                if pending.risky
                    && let Some(earlier) = self.keep.take()
                {
                    self.said = Some(Ok(format!("{}. The change before it is kept: {}.", pending.what, earlier.what.to_lowercase())));
                }
                if pending.risky {
                    self.keeps += 1;
                    self.keep = Some(Keep { what: pending.what.clone(), undo: pending.undo, until: Instant::now() + KEEP, number: self.keeps });
                    self.tick(self.keeps);
                }
            }
            Err(why) => self.said = Some(Err(format!("Nothing was changed: {why}"))),
        }
        self.draft = None;
        self.heard_config(config, fields);
    }

    /// Counts a kept change down, once a second, until it is kept or undone.
    fn tick(&self, number: u64) {
        let window = self.window.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(1));
                let Some(open) = window.upgrade() else { return };
                let mut going = true;
                open.update(|m, _| match &m.keep {
                    Some(keep) if keep.number == number => {
                        if Instant::now() >= keep.until {
                            let keep = m.keep.take().expect("there is one");
                            m.undo(keep, false);
                            going = false;
                        }
                    }
                    _ => going = false,
                });
                if !going {
                    return;
                }
            }
        });
    }

    fn undo(&mut self, keep: Keep, asked: bool) {
        let what = if asked { format!("Undone: {}", keep.what.to_lowercase()) } else { "Not kept in time, so undone".to_string() };
        self.busy = Some(what.clone());
        let window = self.window.clone();
        std::thread::spawn(move || {
            let made = keep.undo.commit();
            let config = machine::read_config();
            if let Some(window) = window.upgrade() {
                window.update(|m, fields| {
                    m.busy = None;
                    m.said = Some(match made {
                        Ok(()) => {
                            m.generation += 1;
                            if asked { Ok(format!("{what}.")) } else { Err(format!("{what}: the previous settings are back.")) }
                        }
                        Err(why) => Err(format!("The change couldn't be undone: {why}")),
                    });
                    m.draft = None;
                    m.heard_config(config, fields);
                });
            }
        });
    }

    // ---- rules ---------------------------------------------------------

    fn open_rule(&mut self, draft: RuleDraft, fields: &mut Fields) {
        self.drawer = Some(Drawer::Rule(draft));
        self.sync_rule(fields);
    }

    /// Puts the rule being written into its fields.
    fn sync_rule(&self, fields: &mut Fields) {
        let Some(Drawer::Rule(d)) = &self.drawer else { return };
        fields.set("r-name", &d.rule.name);
        fields.set("r-prio", &d.rule.priority.map(|p| p.to_string()).unwrap_or_default());
        fields.set("r-on", if d.rule.enabled { "on" } else { "" });
        for (i, c) in d.rule.conds.iter().enumerate() {
            fields.set(&format!("cf{i}"), &c.fact);
            fields.set(&format!("co{i}"), &c.op);
            fields.set(&format!("cv{i}"), &c.text());
        }
        for (i, e) in d.rule.effects().iter().enumerate() {
            fields.set(&format!("fx{i}"), e);
        }
        match d.rule.verdict().and_then(rules::verdict_of) {
            Some(Verdict::Reject { prohibited }) => fields.set("r-rej", if prohibited { "Prohibited" } else { "Refused" }),
            Some(Verdict::Join(p)) => fields.set("r-prof", &p),
            _ => {}
        }
    }

    fn rule_input(&mut self, name: &str, fields: &mut Fields) {
        let Some(Drawer::Rule(d)) = &mut self.drawer else { return };
        let value = fields.get(name).to_string();
        let mut resync = false;
        match name {
            "r-name" if d.path.is_none() => d.rule.name = value.replace(['/', '\\'], "-"),
            "r-prio" => d.rule.priority = value.trim().parse().ok(),
            "r-on" => d.rule.enabled = !value.is_empty(),
            "r-rej" => {
                let effects: Vec<String> = d.rule.effects().into_iter().map(String::from).collect();
                d.rule.actions = std::iter::once(format!("REJECT({})", if value == "Prohibited" { "Prohibited" } else { "Refused" })).chain(effects).collect();
            }
            "r-prof" => d.rule.actions = vec![format!("JOIN({value})")],
            _ => {
                let (kind, index) = name.split_at(2.min(name.len()));
                let Ok(i) = index.parse::<usize>() else { return };
                match kind {
                    "cf" => {
                        if let Some(c) = d.rule.conds.get_mut(i) {
                            c.fact = match value.as_str() {
                                "Counter." => "Counter.name(1m, SrcAddr)".into(),
                                "Tag." => "Tag.name".into(),
                                _ => value.clone(),
                            };
                            c.op = match crate::vocab::lookup(&c.fact).map(|f| f.family) {
                                Some(crate::vocab::Family::Flags) => "Has".into(),
                                _ if c.fact.starts_with("Counter.") => "GreaterThan".into(),
                                _ => "Equal".into(),
                            };
                            c.items = vec![String::new()];
                            resync = true;
                        }
                    }
                    "co" => {
                        if let Some(c) = d.rule.conds.get_mut(i) {
                            c.op = value.clone();
                            if c.op == "Present" {
                                c.items = vec!["1".into()];
                                resync = true;
                            }
                        }
                    }
                    "cv" => {
                        if let Some(c) = d.rule.conds.get_mut(i) {
                            c.items = value.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                            if c.items.is_empty() {
                                c.items.push(String::new());
                            }
                        }
                    }
                    "fx" => {
                        let effects: Vec<String> = d.rule.effects().into_iter().map(String::from).collect();
                        if let Some(old) = effects.get(i)
                            && let Some(at) = d.rule.actions.iter().position(|a| a.trim() == old)
                        {
                            d.rule.actions[at] = value.trim().to_string();
                        }
                    }
                    _ => {}
                }
            }
        }
        if resync {
            self.sync_rule(fields);
        }
    }

    fn new_rule(layer: Layer) -> RuleDraft {
        let mut rule = Rule::new("");
        if layer == Layer::Interface {
            rule.conds = vec![Cond::new("Interface.Kind", "Equal", &["wired"])];
            rule.actions = vec!["JOIN(default)".into()];
        } else {
            rule.conds = vec![Cond::new("Direction", "Equal", &["in"]), Cond::new("Protocol", "Equal", &["tcp"]), Cond::new("DstPort", "Equal", &[""])];
            rule.actions = vec!["PASS".into()];
        }
        RuleDraft { layer, path: None, parent: None, rule }
    }

    fn new_exception(layer: Layer, parent: &str) -> RuleDraft {
        let mut rule = Rule::new("");
        if layer == Layer::Interface {
            rule.conds = vec![Cond::new("Network.Name", "Equal", &[""])];
            rule.actions = vec!["JOIN(default)".into()];
        } else {
            rule.conds = vec![Cond::new("SrcAddr", "Equal", &[""])];
            rule.actions = vec!["DROP".into()];
        }
        RuleDraft { layer, path: None, parent: Some(parent.into()), rule }
    }

    /// Saves the rule being written, if the machine would take it.
    fn save_rule(&mut self) {
        let Some(Drawer::Rule(d)) = &self.drawer else { return };
        if let Err(why) = rules::check_name(&d.rule.name) {
            self.said = Some(Err(why));
            return;
        }
        if d.path.is_none() && rules::find(self.config.policy.forest(d.layer), &d.target()).is_some() {
            self.said = Some(Err(format!("There is already a rule called {}.", d.target())));
            return;
        }
        let policy = d.applied(&self.config.policy);
        let report = engine::check(&policy, &self.subjects());
        if let Some(why) = report.refusals.first() {
            self.said = Some(Err(why.clone()));
            return;
        }
        let target = d.target();
        let mut rule = d.rule.clone();
        rule.name = rule.name.trim().to_string();
        let key = format!("{}\\{}", d.layer.path(), target.replace('/', "\\"));
        let pending = Pending {
            what: format!("{} {target} saved", if d.layer == Layer::Interface { "Profile rule" } else { "Rule" }),
            batch: Batch(vec![Edit::Put { path: key, values: rule.values(), replace: true }]),
            undo: Batch(vec![restore_layer(&self.config, d.layer)]),
            risky: true,
        };
        let cut = self.cut(&policy, None);
        self.drawer = None;
        self.propose(pending, cut);
    }

    fn delete_rule(&mut self, layer: Layer, path: &str) {
        let mut policy = self.config.policy.clone();
        if rules::remove(policy.forest_mut(layer), path).is_none() {
            return;
        }
        let report = engine::check(&policy, &self.subjects());
        if let Some(why) = report.refusals.first() {
            self.said = Some(Err(format!("{path} can't be deleted: {why}")));
            self.modal = None;
            return;
        }
        let pending = Pending {
            what: format!("Rule {path} deleted"),
            batch: Batch(vec![Edit::Delete { path: format!("{}\\{}", layer.path(), path.replace('/', "\\")) }]),
            undo: Batch(vec![restore_layer(&self.config, layer)]),
            risky: true,
        };
        let cut = self.cut(&policy, None);
        self.drawer = None;
        self.modal = None;
        self.propose(pending, cut);
    }

    // ---- profiles ------------------------------------------------------

    fn start_draft(&mut self, fields: &mut Fields) {
        let Some(path) = self.profile.clone() else { return };
        let values = self.config.profiles().and_then(|t| t.at(&path)).map(|t| t.values.clone()).unwrap_or_default();
        let draft = ProfileDraft { path, values };
        for s in crate::vocab::SETTINGS {
            let key = s.key();
            let text = match draft.get(&key) {
                Some(RegValue::List(_)) | None => String::new(),
                Some(v) => v.text(),
            };
            fields.set(&format!("pv:{key}"), &text);
            fields.set(&format!("pa:{key}"), "");
        }
        self.draft = Some(draft);
    }

    fn profile_input(&mut self, name: &str, fields: &mut Fields) {
        let Some(key) = name.strip_prefix("pv:") else { return };
        let Some(setting) = crate::vocab::setting_by(key) else { return };
        let Some(draft) = &mut self.draft else { return };
        let text = fields.get(name).trim().to_string();
        let value = match setting.shape {
            _ if text.is_empty() => None,
            crate::vocab::Shape::Number | crate::vocab::Shape::Tri => Some(text.parse().map(RegValue::Int).unwrap_or(RegValue::Str(text))),
            _ => Some(RegValue::Str(text)),
        };
        draft.set(&setting.key(), value);
    }

    /// The profiles key as the draft would leave it.
    pub fn profiles_with_draft(&self) -> Option<Tree> {
        let mut tree = self.config.profiles().cloned()?;
        if let Some(draft) = &self.draft {
            let mut here = &mut tree;
            for part in draft.path.split('/') {
                let Some(i) = here.children.iter().position(|c| c.name.eq_ignore_ascii_case(part)) else { return Some(tree) };
                here = &mut here.children[i];
            }
            here.values = draft.values.clone();
        }
        Some(tree)
    }

    fn apply_profile(&mut self) {
        let Some(draft) = self.draft.clone() else { return };
        let mut policy = self.config.policy.clone();
        policy.profiles = self.profiles_with_draft();
        let report = engine::check(&policy, &self.subjects());
        if let Some(why) = report.refusals.first() {
            self.said = Some(Err(why.clone()));
            return;
        }
        let used: Vec<String> = self.state.interfaces.iter().filter(|i| i.status.profile.as_deref().is_some_and(|p| p.eq_ignore_ascii_case(&draft.path))).map(|i| i.name().to_string()).collect();
        let carries_desktop = self.state.sessions.iter().any(|s| used.contains(&s.interface));
        let pending = Pending {
            what: format!("Profile {} updated", draft.path.replace('/', " › ")),
            batch: Batch(vec![Edit::Put { path: profile_key(&draft.path), values: draft.values.clone(), replace: true }]),
            undo: Batch(vec![Edit::Restore { path: format!("{}\\Profiles", machine::NETWORK_KEY), tree: self.config.profiles().cloned() }]),
            risky: carries_desktop,
        };
        self.propose(pending, Vec::new());
    }

    fn new_profile(&mut self, inside: bool, fields: &mut Fields) {
        let name = fields.get("np-name").trim().to_string();
        if let Err(why) = rules::check_name(&name) {
            self.said = Some(Err(why.replace("rule", "profile")));
            return;
        }
        let path = match (&self.profile, inside) {
            (Some(p), true) => format!("{p}/{name}"),
            _ => name,
        };
        if self.config.profiles().and_then(|t| t.at(&path)).is_some() {
            self.said = Some(Err(format!("There is already a profile called {path}.")));
            return;
        }
        fields.set("np-name", "");
        let pending = Pending {
            what: format!("Profile {} made", path.replace('/', " › ")),
            batch: Batch(vec![Edit::Put { path: profile_key(&path), values: Vec::new(), replace: false }]),
            undo: Batch(vec![Edit::Delete { path: profile_key(&path) }]),
            risky: false,
        };
        self.profile = Some(path);
        self.draft = None;
        self.propose(pending, Vec::new());
    }

    fn delete_profile(&mut self, path: &str) {
        let mut policy = self.config.policy.clone();
        if let Some(tree) = &mut policy.profiles {
            let (parent, name) = path.rsplit_once('/').map(|(p, n)| (Some(p), n)).unwrap_or((None, path));
            remove_tree(tree, parent, name);
        }
        let report = engine::check(&policy, &self.subjects());
        self.modal = None;
        if let Some(why) = report.refusals.first() {
            self.said = Some(Err(format!("{} can't be deleted: {why}", path.replace('/', " › "))));
            return;
        }
        let pending = Pending {
            what: format!("Profile {} deleted", path.replace('/', " › ")),
            batch: Batch(vec![Edit::Delete { path: profile_key(path) }]),
            undo: Batch(vec![Edit::Restore { path: format!("{}\\Profiles", machine::NETWORK_KEY), tree: self.config.profiles().cloned() }]),
            risky: false,
        };
        self.profile = None;
        self.draft = None;
        self.propose(pending, Vec::new());
    }

    // ---- networks ------------------------------------------------------

    fn open_network(&mut self, id: &str, fields: &mut Fields) {
        let Some(n) = self.config.network(id) else { return };
        fields.set("n-name", n.name.as_deref().unwrap_or_default());
        // A network never given a level is offered as public.
        fields.set("n-trust", n.trust.as_deref().unwrap_or("public"));
        fields.set("n-req", n.requested.as_deref().unwrap_or_default());
        self.drawer = Some(Drawer::Network { id: id.into() });
    }

    /// The network being edited, as its fields would leave it: its id,
    /// name, trust and preferred address.
    pub fn network_edit(&self, fields: &Fields) -> Option<NetworkEdit> {
        let Some(Drawer::Network { id }) = &self.drawer else { return None };
        let opt = |s: &str| Some(s.trim().to_string()).filter(|s| !s.is_empty());
        Some((id.clone(), opt(fields.get("n-name")), opt(fields.get("n-trust")), opt(fields.get("n-req"))))
    }

    fn save_network(&mut self, fields: &mut Fields) {
        let Some((id, name, trust, requested)) = self.network_edit(fields) else { return };
        let Some(old) = self.config.network(&id).cloned() else { return };
        if let Some(r) = &requested
            && r.parse::<std::net::Ipv4Addr>().is_err()
        {
            self.said = Some(Err("A preferred address is an IPv4 address, such as 192.168.1.40.".into()));
            return;
        }
        let key = format!("{}\\Networks\\{id}", machine::NETWORK_KEY);
        let edits = |name: &Option<String>, trust: &Option<String>, requested: &Option<String>| {
            let mut put = Vec::new();
            let mut unset = Vec::new();
            for (value, v) in [("Name", name), ("Trust", trust), ("RequestedAddress", requested)] {
                match v {
                    Some(text) => put.push((value.to_string(), RegValue::Str(text.clone()))),
                    None => unset.push(value.to_string()),
                }
            }
            Batch(vec![Edit::Put { path: key.clone(), values: put, replace: false }, Edit::Unset { path: key.clone(), names: unset }])
        };
        let ctx = Context { id: Some(id.clone()), name: name.clone(), trust: trust.clone(), kind: old.kind.clone() };
        let changes_context = name != old.name || trust != old.trust;
        let cut = if changes_context { self.cut(&self.config.policy, Some((&id, ctx))) } else { Vec::new() };
        let pending = Pending {
            what: format!("{} saved", name.clone().unwrap_or_else(|| "Network".into())),
            batch: edits(&name, &trust, &requested),
            undo: edits(&old.name, &old.trust, &old.requested),
            risky: changes_context && self.state.sessions.iter().any(|s| s.network.id.as_deref() == Some(&id)),
        };
        self.drawer = None;
        self.propose(pending, cut);
    }

    // ---- the exposure matrix -------------------------------------------

    /// The smallest change to the connection rules that opens or closes a
    /// cell, and what it does in words.
    pub fn exposure_change(&self, row: usize, col: Col, open: bool) -> Option<(Policy, String)> {
        let rows = pages::firewall::exposure(self, &self.config.policy);
        let row = rows.get(row)?;
        let cell = row.cells.iter().find(|c| c.col == col)?;
        let mut policy = self.config.policy.clone();
        let other = if col == Col::Private { "public" } else { "private" };
        if !open {
            // Every rule that would still let it through is narrowed in
            // turn, until none does: two rules may allow the same port.
            let mut limited = Vec::new();
            let mut off = Vec::new();
            let mut by = cell.by.clone();
            for _ in 0..8 {
                let Some(root) = by.as_deref().and_then(|b| b.split('/').next()).map(str::to_string) else { break };
                let rule = rules::find_mut(&mut policy.flow, &root)?;
                if rule.conds.iter().any(|c| c.fact == "Network.Trust") {
                    rule.enabled = false;
                    off.push(root);
                } else {
                    rule.conds.push(Cond::new("Network.Trust", "Equal", &[other]));
                    limited.push(root);
                }
                let judge = Judge::new(&policy).ok()?;
                match judge.result(&cell.conn, &engine::no_counts) {
                    Ok(d) if d.passes() => by = d.by,
                    _ => break,
                }
            }
            let names = |list: &[String]| match list {
                [one] => format!("Rule {one}"),
                many => format!("Rules {}", many.join(" and ")),
            };
            let what = match (limited.is_empty(), off.is_empty()) {
                (false, true) => format!("{} limited to {other} networks", names(&limited)),
                (true, false) => format!("{} turned off", names(&off)),
                (false, false) => format!("{} limited to {other} networks; {} turned off", names(&limited), names(&off).to_lowercase()),
                (true, true) => return None,
            };
            return Some((policy, what));
        }
        let flow = &mut policy.flow;
        let port = row.port;
        let found = flow
            .iter()
            .position(|r| r.verdict().and_then(rules::verdict_of) == Some(Verdict::Allow) && r.conds.iter().any(|c| c.fact == "DstPort" && c.op == "Equal" && c.items.iter().any(|v| covers(v, port))));
        if let Some(i) = found {
            let rule = &mut flow[i];
            let name = rule.name.clone();
            let trust = rule.conds.iter().position(|c| c.fact == "Network.Trust");
            if !rule.enabled {
                rule.enabled = true;
                if let Some(t) = trust {
                    rule.conds[t].items = vec![col.id().into()];
                }
                return Some((policy, format!("Rule {name} turned on for {} networks", col.id())));
            }
            if let Some(t) = trust {
                rule.conds.remove(t);
                return Some((policy, format!("Rule {name} now applies to every network")));
            }
        }
        let name = format!("allow-{}-{}", row.service.clone().unwrap_or_else(|| format!("port-{port}")), col.id());
        let mut rule = Rule::new(&name);
        rule.conds = vec![
            Cond::new("Direction", "Equal", &["in"]),
            Cond::new("Protocol", "Equal", &[&row.protocol]),
            Cond::new("DstPort", "Equal", &[&port.to_string()]),
            Cond::new("Network.Trust", "Equal", &[col.id()]),
        ];
        rule.actions = vec!["PASS".into()];
        flow.push(rule);
        Some((policy, format!("Rule {name} added")))
    }

    fn set_cell(&mut self, open: bool) {
        let Some(Drawer::Trace(Trace { cell: Some((row, col)), .. })) = &self.drawer else { return };
        let Some((policy, what)) = self.exposure_change(*row, *col, open) else {
            self.said = Some(Err("No one rule decides this alone: change it in Rules.".into()));
            return;
        };
        let report = engine::check(&policy, &self.subjects());
        if let Some(why) = report.refusals.first() {
            self.said = Some(Err(why.clone()));
            return;
        }
        let mut layer = Tree::new("Flow");
        layer.children = policy.flow.iter().map(Rule::tree).collect();
        let pending = Pending {
            what,
            batch: Batch(vec![Edit::Restore { path: Layer::Flow.path(), tree: Some(layer) }]),
            undo: Batch(vec![restore_layer(&self.config, Layer::Flow)]),
            risky: true,
        };
        let cut = self.cut(&policy, None);
        self.drawer = None;
        self.propose(pending, cut);
    }

    // ---- name resolution -----------------------------------------------

    fn look_up(&mut self, fields: &Fields) {
        let name = fields.get("lk-q").trim().trim_end_matches('.').to_string();
        if name.is_empty() {
            return;
        }
        let aaaa = fields.get("lk-t") == "AAAA";
        self.lookup = Lookup { name: name.clone(), aaaa, answer: None, asking: true };
        let window = self.window.clone();
        std::thread::spawn(move || {
            let asked = machine::resolvd(&libresolv::Request::Resolve { name, rtype: if aaaa { 28 } else { 1 }, no_cache: false });
            let answer = match asked {
                Ok(libresolv::Reply::Answer(a)) => Ok(a),
                Ok(_) => Err("resolvd answered something else.".to_string()),
                Err(e) => Err(e),
            };
            if let Some(window) = window.upgrade() {
                window.update(|m, _| {
                    m.lookup.answer = Some(answer);
                    m.lookup.asking = false;
                });
            }
        });
    }

    fn dns_put(&mut self, what: String, values: Vec<(String, RegValue)>, unset: Vec<String>) {
        let key = format!("{}\\Dns", machine::NETWORK_KEY);
        let old: Vec<(String, RegValue)> = [("FallbackServers", &self.config.fallback), ("ExtraSearchDomains", &self.config.extra_domains)]
            .into_iter()
            .filter(|(n, list)| !list.is_empty() && (values.iter().any(|(v, _)| v == n) || unset.iter().any(|u| u == n)))
            .map(|(n, list)| (n.to_string(), RegValue::List(list.clone())))
            .collect();
        let gone: Vec<String> = values.iter().map(|(n, _)| n.clone()).filter(|n| !old.iter().any(|(o, _)| o == n)).collect();
        let pending = Pending {
            what,
            batch: Batch(vec![Edit::Put { path: key.clone(), values, replace: false }, Edit::Unset { path: key.clone(), names: unset }]),
            undo: Batch(vec![Edit::Put { path: key.clone(), values: old, replace: false }, Edit::Unset { path: key, names: gone }]),
            risky: false,
        };
        self.propose(pending, Vec::new());
    }

    fn dns_list(&mut self, which: &str, list: Vec<String>, what: String) {
        let name = if which == "fallback" { "FallbackServers" } else { "ExtraSearchDomains" };
        if list.is_empty() {
            self.dns_put(what, Vec::new(), vec![name.into()]);
        } else {
            self.dns_put(what, vec![(name.into(), RegValue::List(list))], Vec::new());
        }
    }

    fn hosts(&mut self, what: String, add: Option<(String, String)>, remove: Option<String>) {
        let key = format!("{}\\Dns\\Hosts", machine::NETWORK_KEY);
        let mut batch = Batch::default();
        let mut undo = Batch::default();
        if let Some((name, addr)) = add {
            let old = self.config.hosts.iter().find(|(n, _)| n.eq_ignore_ascii_case(&name)).map(|(_, a)| a.clone());
            batch.push(Edit::Put { path: key.clone(), values: vec![(name.clone(), RegValue::Str(addr))], replace: false });
            undo.push(match old {
                Some(a) => Edit::Put { path: key.clone(), values: vec![(name, RegValue::Str(a))], replace: false },
                None => Edit::Unset { path: key.clone(), names: vec![name] },
            });
        }
        if let Some(name) = remove {
            if let Some((n, a)) = self.config.hosts.iter().find(|(n, _)| n.eq_ignore_ascii_case(&name)) {
                undo.push(Edit::Put { path: key.clone(), values: vec![(n.clone(), RegValue::Str(a.clone()))], replace: false });
            }
            batch.push(Edit::Unset { path: key, names: vec![name] });
        }
        self.propose(Pending { what, batch, undo, risky: false }, Vec::new());
    }

    // ---- the person's descriptors ---------------------------------------

    /// Opens the permissions editor on a descriptor kept as a registry
    /// value, which applying writes back.
    fn edit_permissions(&mut self, what: &str, key: String, value: String, current: Vec<u8>, rights: Vec<gxwi_sd_editor::Right>, generic: gxwi_sd_editor::Generic) {
        if self.editing {
            return;
        }
        let may = registry_may(&key);
        let window = self.window.clone();
        let request = gxwi_sd_editor::Request {
            object: gxwi_sd_editor::Object { name: what.into(), kind: "Setting".into(), container: false, children: gxwi_sd_editor::Children::All },
            sd: current.clone(),
            rights,
            generic,
            can: gxwi_sd_editor::Can { dacl: may, owner: may, audit: false, why: (!may).then(|| ui::LOCKED.to_string()) },
        };
        let mut held = current;
        let apply_window = self.window.clone();
        let opened = gxwi_sd_editor::edit(
            &request,
            move |sd, parts| {
                let whole = gxwi_sd_editor::splice(&held, sd, parts)?;
                Batch(vec![Edit::Put { path: key.clone(), values: vec![(value.clone(), RegValue::Bytes(whole.clone()))], replace: false }]).commit()?;
                held = whole;
                if let Some(window) = apply_window.upgrade() {
                    window.update(|m, _| m.reread());
                }
                Ok(())
            },
            move || {
                if let Some(window) = window.upgrade() {
                    window.update(|m, _| m.editing = false);
                }
            },
        );
        match opened {
            Ok(()) => self.editing = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => self.said = Some(Err("The permissions editor isn't installed.".into())),
            Err(e) => self.said = Some(Err(format!("The permissions editor couldn't be opened: {e}."))),
        }
    }

    fn permissions(&mut self, which: &str, fields: &mut Fields) {
        match which {
            "netd" | "resolvd" => {
                let (key, current, what) = if which == "netd" {
                    (machine::NETWORK_KEY.to_string(), self.config.netd_security.clone(), "Network configuration (netd)")
                } else {
                    (format!("{}\\Dns", machine::NETWORK_KEY), self.config.resolvd_security.clone(), "Name resolution (resolvd)")
                };
                let current = current.unwrap_or_else(|| sddl(CONTROL_DEFAULT));
                let rights = vec![
                    gxwi_sd_editor::Right { name: "Control".into(), mask: 0x000F_0003, general: true },
                    gxwi_sd_editor::Right { name: "Query".into(), mask: 0x1, general: true },
                ];
                let generic = gxwi_sd_editor::Generic { read: 0x1, write: 0x2, execute: 0x1, all: 0x000F_0003 };
                self.edit_permissions(what, key, "ControlSecurity".into(), current, rights, generic);
            }
            "new-reservation" => {
                let selector = fields.get("res-new").trim().to_ascii_lowercase().replace(' ', "");
                if machine::parse_selector(&selector).is_none() {
                    self.said = Some(Err("Write a reservation as protocols and ports: tcp:8443, or tcp,udp:5000-5100.".into()));
                    return;
                }
                if self.config.reservations.iter().any(|r| r.selector == selector) {
                    self.said = Some(Err(format!("{selector} is reserved already: change its permissions.")));
                    return;
                }
                let sd = sddl(RESERVATION_DEFAULT);
                let pending = Pending {
                    what: format!("Reservation {selector} added: SYSTEM and Administrators may listen"),
                    batch: Batch(vec![Edit::Put { path: machine::RESERVATIONS_KEY.into(), values: vec![(selector.clone(), RegValue::Bytes(sd))], replace: false }]),
                    undo: Batch(vec![Edit::Unset { path: machine::RESERVATIONS_KEY.into(), names: vec![selector] }]),
                    risky: false,
                };
                fields.set("res-new", "");
                self.propose(pending, Vec::new());
            }
            selector => {
                let Some(r) = self.config.reservations.iter().find(|r| r.selector == selector) else { return };
                let rights = vec![gxwi_sd_editor::Right { name: "Listen".into(), mask: 0x1, general: true }];
                let generic = gxwi_sd_editor::Generic { read: 0, write: 0, execute: 0x1, all: 0x1 };
                let what = if r.is_default() { "Ports without a reservation".to_string() } else { format!("Ports {}", r.selector) };
                self.edit_permissions(&what, machine::RESERVATIONS_KEY.into(), r.selector.clone(), r.sd.clone(), rights, generic);
            }
        }
    }

    fn remove_reservation(&mut self, selector: &str) {
        let Some(r) = self.config.reservations.iter().find(|r| r.selector == selector && !r.is_default()) else { return };
        let pending = Pending {
            what: format!("Reservation {selector} removed"),
            batch: Batch(vec![Edit::Unset { path: machine::RESERVATIONS_KEY.into(), names: vec![selector.into()] }]),
            undo: Batch(vec![Edit::Put { path: machine::RESERVATIONS_KEY.into(), values: vec![(selector.into(), RegValue::Bytes(r.sd.clone()))], replace: false }]),
            risky: false,
        };
        self.propose(pending, Vec::new());
    }

    // ---- the trace -----------------------------------------------------

    fn open_trace(&mut self, trace: Trace, fields: &mut Fields) {
        let c = &trace.conn;
        fields.set("t-dir", if c.inbound { "in" } else { "out" });
        fields.set("t-proto", &c.protocol);
        fields.set("t-remote", &c.remote);
        fields.set("t-port", &c.port().to_string());
        let net = if c.interface == "lo" {
            "lo".to_string()
        } else {
            match (&c.network.id, &c.network.trust) {
                (Some(id), _) if self.config.network(id).is_some() => id.clone(),
                (_, Some(t)) => format!("trust:{t}"),
                _ => "none".into(),
            }
        };
        fields.set("t-net", &net);
        fields.set("t-svc", c.service.as_deref().unwrap_or_default());
        self.drawer = Some(Drawer::Trace(trace));
    }

    fn trace_input(&mut self, name: &str, fields: &mut Fields) {
        let interface = self.state.online().or(self.state.interfaces.first()).map(|i| i.name().to_string()).unwrap_or_else(|| "eth0".into());
        let here = self.state.interface(&interface).and_then(|i| i.status.addresses.iter().find(|a| !a.contains(':'))).map(|a| a.split('/').next().unwrap_or_default().to_string()).unwrap_or_else(|| "192.0.2.10".into());
        let networks = self.config.networks.clone();
        let Some(Drawer::Trace(t)) = &mut self.drawer else { return };
        let value = fields.get(name).trim().to_string();
        let c = &mut t.conn;
        match name {
            "t-dir" => {
                let port = c.port();
                c.inbound = value != "out";
                if c.inbound {
                    c.local_port = port;
                    c.remote_port = 51544;
                } else {
                    c.remote_port = port;
                    c.local_port = 52210;
                }
            }
            "t-proto" => c.protocol = value,
            "t-remote" => c.remote = value,
            "t-port" => {
                let port = value.parse().unwrap_or(0);
                if c.inbound { c.local_port = port } else { c.remote_port = port }
            }
            "t-svc" => c.service = Some(value).filter(|s| !s.is_empty()),
            "t-net" => {
                if value == "lo" {
                    c.interface = "lo".into();
                    c.local = "127.0.0.1".into();
                    c.network = Context::default();
                } else {
                    c.interface = interface;
                    c.local = here;
                    c.network = if let Some(t) = value.strip_prefix("trust:") {
                        Context { trust: Some(t.into()), ..Context::default() }
                    } else {
                        networks.iter().find(|n| n.id == value).map(|n| n.context()).unwrap_or_default()
                    };
                }
            }
            _ => return,
        }
        t.layer = None;
    }

    /// Example connections to test.
    pub fn preset(&self, which: &str) -> Conn {
        let interface = self.state.online().or(self.state.interfaces.first());
        let iface = interface.map(|i| i.name().to_string()).unwrap_or_else(|| "eth0".into());
        let network = interface.map(|i| i.subject(&self.config).network).unwrap_or_default();
        let here = interface.and_then(|i| i.status.addresses.iter().find(|a| !a.contains(':'))).map(|a| a.split('/').next().unwrap_or_default().to_string()).unwrap_or_else(|| "192.0.2.10".into());
        let base = Conn { interface: iface, local: here, network: network.clone(), ..Conn::default() };
        match which {
            "you" => self.state.sessions.first().cloned().map(|mut s| {
                s.established = false;
                s
            }).unwrap_or(Conn { local_port: self.config.desktop_port, service: Some("gxwid".into()), remote: "192.168.1.23".into(), ..base }),
            "public-ssh" => Conn { remote: "10.99.3.41".into(), local_port: 22, service: Some("sshd".into()), network: Context { trust: Some("public".into()), ..Context::default() }, ..base },
            "flood" => Conn { remote: "203.0.113.50".into(), local_port: 22, service: Some("sshd".into()), ..base },
            "stray" => Conn { remote: "198.51.100.7".into(), local_port: 3389, ..base },
            _ => Conn { inbound: false, remote: "151.101.2.132".into(), remote_port: 443, local_port: 52210, service: Some("peipkg".into()), ..base },
        }
    }
}

/// What restores a layer's rules exactly as they were read.
fn restore_layer(config: &Config, layer: Layer) -> Edit {
    Edit::Restore { path: layer.path(), tree: config.rules.as_ref().and_then(|r| r.child(layer.key())).cloned() }
}

fn profile_key(path: &str) -> String {
    format!("{}\\Profiles\\{}", machine::NETWORK_KEY, path.replace('/', "\\"))
}

fn remove_tree(tree: &mut Tree, parent: Option<&str>, name: &str) {
    let list = match parent {
        Some(p) => {
            let mut here = &mut *tree;
            for part in p.split('/') {
                let Some(i) = here.children.iter().position(|c| c.name.eq_ignore_ascii_case(part)) else { return };
                here = &mut here.children[i];
            }
            &mut here.children
        }
        None => &mut tree.children,
    };
    list.retain(|c| !c.name.eq_ignore_ascii_case(name));
}

fn covers(item: &str, port: u16) -> bool {
    match item.split_once('-') {
        Some((lo, hi)) => matches!((lo.trim().parse::<u16>(), hi.trim().parse::<u16>()), (Ok(lo), Ok(hi)) if lo <= port && port <= hi),
        None => item.trim().parse() == Ok(port),
    }
}

fn registry_may(key: &str) -> bool {
    crate::registry::may_change(key)
}

/// netd's and resolvd's compiled default: everyone may query, SYSTEM and
/// Administrators may control.
const CONTROL_DEFAULT: &str = "O:SYG:SYD:(A;;0x1;;;WD)(A;;0xF0003;;;SY)(A;;0xF0003;;;BA)";
/// A new reservation: SYSTEM and Administrators may listen.
const RESERVATION_DEFAULT: &str = "O:SYG:SYD:(A;;0x1;;;SY)(A;;0x1;;;BA)";

fn sddl(text: &str) -> Vec<u8> {
    peios::security::sddl::parse(text).map(|sd| sd.as_bytes().to_vec()).unwrap_or_default()
}

impl Surfaced for Manager {
    fn render(&self, facts: &Facts) -> String {
        pages::render(self, facts.fields)
    }

    fn input(&mut self, name: &str, fields: &mut Fields) {
        match self.drawer {
            Some(Drawer::Rule(_)) => self.rule_input(name, fields),
            Some(Drawer::Trace(_)) => self.trace_input(name, fields),
            _ => {}
        }
        if name.starts_with("pv:") {
            self.profile_input(name, fields);
        }
    }

    fn event(&mut self, name: &str, value: &Value, fields: &mut Fields) {
        let v = |key: &str| named(value, key);
        match name {
            "section" => {
                if let Some(view) = View::by(&v("section")) {
                    self.view = view;
                    self.drawer = None;
                    self.said = None;
                    if view == View::Advanced {
                        for i in &self.config.inventory {
                            fields.set(&format!("cid:{}", i.id), i.client_id.as_deref().unwrap_or_default());
                        }
                    }
                }
            }
            "select" => self.selected = Some(v("i")),
            "go-profile" => {
                self.view = View::Profiles;
                self.drawer = None;
                self.profile = Some(v("p"));
                self.start_draft(fields);
            }
            "go" => {
                if let Some(view) = View::by(&v("view")) {
                    self.view = view;
                    self.drawer = None;
                }
            }
            "close" => self.drawer = None,
            "modal-cancel" => self.modal = None,
            "modal-go" => match self.modal.take() {
                Some(Modal::Cutoff { pending, .. }) => self.commit(Pending { risky: true, ..pending }),
                Some(Modal::DeleteRule { layer, path, .. }) => self.delete_rule(layer, &path),
                Some(Modal::DeleteProfile { path }) => self.delete_profile(&path),
                None => {}
            },
            "keep" => {
                if let Some(keep) = self.keep.take() {
                    self.said = Some(Ok(format!("{}: kept.", keep.what)));
                }
            }
            "revert" => {
                if let Some(keep) = self.keep.take() {
                    self.undo(keep, true);
                }
            }
            "open-network" => self.open_network(&v("id"), fields),
            "net-save" => self.save_network(fields),
            "renew" | "reconcile" => {
                let interface = v("i");
                let request = if name == "renew" { libnetd::Request::Renew { interface: interface.clone() } } else { libnetd::Request::Reconcile };
                self.renewing = Some(if name == "renew" { interface.clone() } else { String::new() });
                let window = self.window.clone();
                std::thread::spawn(move || {
                    let done = machine::netd(&request);
                    if let Some(window) = window.upgrade() {
                        window.update(|m, _| {
                            m.renewing = None;
                            m.said = Some(done.map(|()| if interface.is_empty() { "netd made every interface match its profile again.".to_string() } else { format!("{interface} asked its network for a fresh lease.") }));
                        });
                    }
                });
            }
            "profile-select" => {
                self.profile = Some(v("p"));
                self.start_draft(fields);
            }
            "profile-new" => self.new_profile(v("where") == "inside", fields),
            "profile-delete" => {
                if let Some(p) = self.profile.clone() {
                    self.modal = Some(Modal::DeleteProfile { path: p });
                }
            }
            "pv-set" => {
                let key = v("k");
                let value = v("v");
                if let Some(d) = &mut self.draft {
                    d.set(&key, value.parse().ok().map(RegValue::Int));
                }
            }
            "pv-clear" => {
                let key = v("k");
                if let Some(d) = &mut self.draft {
                    d.set(&key, None);
                }
                fields.set(&format!("pv:{key}"), "");
            }
            "pv-del" => {
                let key = v("k");
                let at: usize = v("i").parse().unwrap_or(usize::MAX);
                if let Some(d) = &mut self.draft {
                    let mut list = d.get(&key).and_then(RegValue::as_list).unwrap_or_default();
                    if at < list.len() {
                        list.remove(at);
                    }
                    d.set(&key, Some(RegValue::List(list)));
                }
            }
            "pv-add" => {
                let key = v("k");
                let typed = fields.get(&format!("pa:{key}")).trim().to_string();
                if typed.is_empty() {
                    return;
                }
                if let Some(d) = &mut self.draft {
                    let mut list = d.get(&key).and_then(RegValue::as_list).unwrap_or_default();
                    list.extend(typed.split([',', ' ']).filter(|s| !s.is_empty()).map(String::from));
                    d.set(&key, Some(RegValue::List(list)));
                }
                fields.set(&format!("pa:{key}"), "");
            }
            "profile-discard" => self.start_draft(fields),
            "profile-apply" => self.apply_profile(),
            "rule-open" => {
                let Some(layer) = Layer::by(&v("layer")) else { return };
                let path = v("p");
                let Some(rule) = rules::find(self.config.policy.forest(layer), &path).cloned() else { return };
                let parent = path.rsplit_once('/').map(|(p, _)| p.to_string());
                self.open_rule(RuleDraft { layer, path: Some(path), parent, rule }, fields);
            }
            "rule-new" => {
                let Some(layer) = Layer::by(&v("layer")) else { return };
                self.open_rule(Self::new_rule(layer), fields);
            }
            "rule-new-for" => {
                let i = v("i");
                let mut draft = Self::new_rule(Layer::Interface);
                draft.rule.name = i.clone();
                let id = self.state.interface(&i).map(|x| x.status.ifid.clone()).unwrap_or_default();
                draft.rule.conds = vec![Cond::new("Interface.Id", "Equal", &[&id])];
                self.view = View::Assign;
                self.open_rule(draft, fields);
            }
            "rule-child-of" => {
                let Some(layer) = Layer::by(&v("layer")) else { return };
                self.open_rule(Self::new_exception(layer, &v("p")), fields);
            }
            "rule-child" => {
                if let Some(Drawer::Rule(d)) = &self.drawer
                    && let Some(path) = d.path.clone()
                {
                    let layer = d.layer;
                    self.open_rule(Self::new_exception(layer, &path), fields);
                }
            }
            "rv" => {
                if let Some(Drawer::Rule(d)) = &mut self.drawer {
                    let effects: Vec<String> = d.rule.effects().into_iter().map(String::from).collect();
                    let current = d.rule.verdict().and_then(rules::verdict_of);
                    let main = match v("v").as_str() {
                        "JOIN" => Some(match current {
                            Some(Verdict::Join(p)) => format!("JOIN({p})"),
                            _ => "JOIN(default)".into(),
                        }),
                        "REJECT" => Some(match current {
                            Some(r @ Verdict::Reject { .. }) => r.action(),
                            _ => "REJECT(Refused)".into(),
                        }),
                        "" => None,
                        other => Some(other.to_string()),
                    };
                    d.rule.actions = main.into_iter().chain(effects).collect();
                }
                self.sync_rule(fields);
            }
            "cond-add" => {
                if let Some(Drawer::Rule(d)) = &mut self.drawer {
                    let fact = if d.layer == Layer::Interface { "Network.Name" } else { "SrcAddr" };
                    d.rule.conds.push(Cond::new(fact, "Equal", &[""]));
                }
                self.sync_rule(fields);
            }
            "cond-del" => {
                let at: usize = v("i").parse().unwrap_or(usize::MAX);
                if let Some(Drawer::Rule(d)) = &mut self.drawer
                    && at < d.rule.conds.len()
                {
                    d.rule.conds.remove(at);
                }
                self.sync_rule(fields);
            }
            "fx-add" => {
                if let Some(Drawer::Rule(d)) = &mut self.drawer {
                    d.rule.actions.push(v("e"));
                }
                self.sync_rule(fields);
            }
            "fx-del" => {
                let at: usize = v("i").parse().unwrap_or(usize::MAX);
                if let Some(Drawer::Rule(d)) = &mut self.drawer {
                    let effects: Vec<String> = d.rule.effects().into_iter().map(String::from).collect();
                    if let Some(e) = effects.get(at)
                        && let Some(i) = d.rule.actions.iter().position(|a| a.trim() == e)
                    {
                        d.rule.actions.remove(i);
                    }
                }
                self.sync_rule(fields);
            }
            "rule-save" => self.save_rule(),
            "rule-delete" => {
                if let Some(Drawer::Rule(d)) = &self.drawer
                    && let Some(path) = &d.path
                {
                    let exceptions = rules::find(self.config.policy.forest(d.layer), path).map(|r| rules::count(&r.children)).unwrap_or(0);
                    self.modal = Some(Modal::DeleteRule { layer: d.layer, path: path.clone(), exceptions });
                }
            }
            "rule-test" => {
                if let Some(Drawer::Rule(d)) = &self.drawer {
                    let first = |fact: &str| d.rule.conds.iter().chain(d.parent.as_deref().and_then(|p| rules::find(self.config.policy.forest(d.layer), p)).map(|r| r.conds.iter()).into_iter().flatten()).find(|c| c.fact == fact && c.op == "Equal").and_then(|c| c.items.first().cloned());
                    let mut conn = self.preset("stray");
                    conn.inbound = first("Direction").as_deref() != Some("out");
                    if let Some(p) = first("Protocol") {
                        conn.protocol = p;
                    }
                    if let Some(port) = first("DstPort").and_then(|p| p.split('-').next().and_then(|p| p.trim().parse().ok())) {
                        if conn.inbound { conn.local_port = port } else { conn.remote_port = port }
                    }
                    if let Some(addr) = first("SrcAddr") {
                        conn.remote = addr.split(['/', '-']).next().unwrap_or_default().to_string();
                    }
                    if let Some(t) = first("Network.Trust") {
                        conn.network = Context { trust: Some(t), ..Context::default() };
                    }
                    self.open_trace(Trace { conn, edit: true, cell: None, layer: None, title: "Test a connection".into() }, fields);
                }
            }
            "layer" => {
                if let Some(l) = Layer::by(&v("l")) {
                    self.layer = l;
                }
            }
            "tab" => self.tab = if v("t") == "counters" { Tab::Counters } else { Tab::Connections },
            "cell" => {
                let Ok(row) = v("r").parse::<usize>() else { return };
                let Some(col) = Col::by(&v("k")) else { return };
                let rows = pages::firewall::exposure(self, &self.config.policy);
                let Some(r) = rows.get(row) else { return };
                let Some(cell) = r.cells.iter().find(|c| c.col == col) else { return };
                let trace = Trace { conn: cell.conn.clone(), edit: false, cell: (col != Col::Local).then_some((row, col)), layer: None, title: format!("{} · {}", r.title, pages::firewall::col_title(col)) };
                self.open_trace(trace, fields);
            }
            "cell-set" => self.set_cell(v("open") == "1"),
            "flow" => {
                let Ok(i) = v("i").parse::<usize>() else { return };
                let Some(flow) = self.live.flows.get(i) else { return };
                let conn = live::conn(flow, &self.config, &self.state);
                self.open_trace(Trace { conn, edit: false, cell: None, layer: None, title: "Connection".into() }, fields);
            }
            "test-open" => {
                let conn = self.preset("flood");
                self.open_trace(Trace { conn, edit: true, cell: None, layer: None, title: "Test a connection".into() }, fields);
            }
            "preset" => {
                let conn = self.preset(&v("k"));
                self.open_trace(Trace { conn, edit: true, cell: None, layer: None, title: "Test a connection".into() }, fields);
            }
            "trace-layer" => {
                if let Some(Drawer::Trace(t)) = &mut self.drawer {
                    t.layer = Layer::by(&v("l"));
                }
            }
            "allow-this" => {
                if let Some(Drawer::Trace(t)) = &self.drawer {
                    let c = t.conn.clone();
                    let mut draft = Self::new_rule(Layer::Flow);
                    draft.rule.name = format!("allow-{}-{}", c.protocol, c.port());
                    draft.rule.conds = vec![Cond::new("Direction", "Equal", &["in"]), Cond::new("Protocol", "Equal", &[&c.protocol]), Cond::new("DstPort", "Equal", &[&c.port().to_string()]), Cond::new("SrcAddr", "Equal", &[&c.remote])];
                    self.view = View::Rules;
                    self.layer = Layer::Flow;
                    self.open_rule(draft, fields);
                }
            }
            "lookup" => self.look_up(fields),
            "flush" => {
                let window = self.window.clone();
                std::thread::spawn(move || {
                    let done = machine::resolvd(&libresolv::Request::Flush);
                    if let Some(window) = window.upgrade() {
                        window.update(|m, _| {
                            m.said = Some(done.map(|_| "The DNS cache is empty.".to_string()).map_err(|e| format!("The cache wasn't flushed: {e}")));
                        });
                    }
                });
            }
            "dns-add" => {
                let which = v("k");
                let field = format!("da-{which}");
                let typed: Vec<String> = fields.get(&field).split([',', ' ']).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                if typed.is_empty() {
                    return;
                }
                if which == "fallback"
                    && let Some(bad) = typed.iter().find(|s| s.parse::<std::net::IpAddr>().is_err())
                {
                    self.said = Some(Err(format!("{bad} isn't an address. A server is written as one, such as 9.9.9.9.")));
                    return;
                }
                let mut list = if which == "fallback" { self.config.fallback.clone() } else { self.config.extra_domains.clone() };
                list.extend(typed);
                fields.set(&field, "");
                self.dns_list(&which, list, if which == "fallback" { "Fallback servers saved".into() } else { "Search domains saved".into() });
            }
            "dns-del" => {
                let which = v("k");
                let at: usize = v("i").parse().unwrap_or(usize::MAX);
                let mut list = if which == "fallback" { self.config.fallback.clone() } else { self.config.extra_domains.clone() };
                if at < list.len() {
                    let gone = list.remove(at);
                    self.dns_list(&which, list, format!("{gone} removed"));
                }
            }
            "host-add" => {
                let name = fields.get("hn").trim().to_ascii_lowercase();
                let addr = fields.get("ha").trim().to_string();
                if name.is_empty() || addr.parse::<std::net::IpAddr>().is_err() {
                    self.said = Some(Err("Give a name and an address, such as printer and 192.168.1.12.".into()));
                    return;
                }
                if name.contains(char::is_whitespace) || name.starts_with('.') || name.ends_with('.') {
                    self.said = Some(Err(format!("{name} isn't a name a machine can have.")));
                    return;
                }
                fields.set("hn", "");
                fields.set("ha", "");
                self.hosts(format!("{name} added"), Some((name, addr)), None);
            }
            "host-del" => {
                let name = v("n");
                self.hosts(format!("{name} removed"), None, Some(name));
            }
            "port-check" => {
                self.port_check = Some(PortCheck { port: fields.get("pc-port").trim().into(), protocol: fields.get("pc-proto").into(), who: fields.get("pc-who").into() });
            }
            "perm" => self.permissions(&v("w"), fields),
            "res-remove" => self.remove_reservation(&v("w")),
            "audit-level" => {
                let n: i64 = v("n").parse().unwrap_or(1).clamp(1, 6);
                if n as u8 == self.config.reporting {
                    return;
                }
                let key = format!("{}\\Rules", machine::NETWORK_KEY);
                let pending = Pending {
                    what: if n == 6 { "Firewall auditing turned off".into() } else { format!("Audit events from level {n} up are recorded") },
                    batch: Batch(vec![Edit::Put { path: key.clone(), values: vec![("CurrentReportingLevel".into(), RegValue::Int(n))], replace: false }]),
                    undo: Batch(vec![Edit::Put { path: key, values: vec![("CurrentReportingLevel".into(), RegValue::Int(i64::from(self.config.reporting)))], replace: false }]),
                    risky: false,
                };
                self.propose(pending, Vec::new());
            }
            "client-id" => {
                let id = v("id");
                let typed = fields.get(&format!("cid:{id}")).trim().to_ascii_lowercase();
                let key = format!("{}\\Interfaces\\{id}", machine::NETWORK_KEY);
                let old = self.config.inventory.iter().find(|i| i.id == id).and_then(|i| i.client_id.clone());
                if !typed.is_empty() && !hex_id(&typed) {
                    self.said = Some(Err("A client ID is bytes in hex, such as 01:52:54:00:12:34:56.".into()));
                    return;
                }
                let set = |v: &Option<String>| match v {
                    Some(text) => Edit::Put { path: key.clone(), values: vec![("ClientId".into(), RegValue::Str(text.clone()))], replace: false },
                    None => Edit::Unset { path: key.clone(), names: vec!["ClientId".into()] },
                };
                let new = Some(typed).filter(|t| !t.is_empty());
                let pending = Pending { what: "Client ID saved".into(), batch: Batch(vec![set(&new)]), undo: Batch(vec![set(&old)]), risky: false };
                self.propose(pending, Vec::new());
            }
            _ => {}
        }
    }
}

/// Bytes in hex, colon-separated or not, as netd reads `ClientId`.
fn hex_id(text: &str) -> bool {
    let digits: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    !digits.is_empty() && digits.len().is_multiple_of(2) && text.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_section_names_a_view() {
        for view in View::ALL {
            assert_eq!(View::by(view.id()), Some(view));
        }
    }

    #[test]
    fn a_draft_rule_lands_where_its_parent_is() {
        let policy = engine::tests::seed();
        let mut draft = Manager::new_exception(Layer::Flow, "ssh");
        draft.rule.name = "lan".into();
        draft.rule.conds = vec![Cond::new("SrcAddr", "Equal", &["10.0.0.0/8"])];
        assert_eq!(draft.target(), "ssh/lan");
        let applied = draft.applied(&policy);
        assert!(rules::find(&applied.flow, "ssh/lan").is_some());
        assert!(rules::find(&applied.flow, "ssh/too-fast").is_some());
    }

    #[test]
    fn a_closed_port_opens_by_the_smallest_change() {
        let mut m = Manager::new();
        m.config.policy = engine::tests::seed();
        rules::find_mut(&mut m.config.policy.flow, "ssh").unwrap().conds.push(Cond::new("Network.Trust", "Equal", &["private"]));
        let rows = pages::firewall::exposure(&m, &m.config.policy);
        let ssh = rows.iter().position(|r| r.port == 22).unwrap();
        let (policy, what) = m.exposure_change(ssh, Col::Public, true).unwrap();
        assert_eq!(what, "Rule ssh now applies to every network");
        assert!(!rules::find(&policy.flow, "ssh").unwrap().conds.iter().any(|c| c.fact == "Network.Trust"));
        let (policy, what) = m.exposure_change(ssh, Col::Private, false).unwrap();
        assert_eq!(what, "Rule ssh turned off");
        assert!(!rules::find(&policy.flow, "ssh").unwrap().enabled);
    }

    #[test]
    fn a_port_two_rules_allow_is_closed_by_narrowing_both() {
        let mut m = Manager::new();
        m.config.policy = engine::tests::seed();
        let mut twin = rules::find(&m.config.policy.flow, "gxwi-experimental").unwrap().clone();
        twin.name = "dev-gxwi".into();
        m.config.policy.flow.push(twin);
        m.config.desktop_port = 7780;
        m.relive();
        let rows = pages::firewall::exposure(&m, &m.config.policy);
        let desktop = rows.iter().position(|r| r.port == 7780).unwrap();
        let (policy, what) = m.exposure_change(desktop, Col::Private, false).unwrap();
        assert!(what.starts_with("Rules ") && what.contains("gxwi-experimental") && what.contains("dev-gxwi"), "{what}");
        let after = pages::firewall::exposure(&m, &policy);
        assert!(!after[desktop].cells.iter().find(|c| c.col == Col::Private).unwrap().open());
        assert!(after[desktop].cells.iter().find(|c| c.col == Col::Public).unwrap().open());
    }

    #[test]
    fn client_ids_are_hex() {
        assert!(hex_id("01:52:54:00:12:34:56"));
        assert!(!hex_id("01:5"));
        assert!(!hex_id("zz"));
    }
}
