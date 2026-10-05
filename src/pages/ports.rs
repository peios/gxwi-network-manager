//! Port reservations: who may listen on a port. Each is a descriptor over a
//! range of ports; a port takes its narrowest reservation, and one with
//! none takes the default.

use crate::machine::{self, Reservation};
use crate::manager::Manager;
use crate::ui::{h, locked, phead, select, svg, values, LOCKED};

/// The right a reservation grants: to bind.
const BIND: u32 = 0x1;

/// Who a port can be checked for, with the SIDs their token holds.
fn principals() -> Vec<(String, String, Vec<String>)> {
    let everyone = ["S-1-1-0".to_string(), "S-1-5-11".to_string()];
    let mut out = vec![
        ("system".to_string(), "SYSTEM".to_string(), [vec!["S-1-5-18".to_string()], everyone.to_vec()].concat()),
        ("admin".into(), "An administrator".into(), [vec!["S-1-5-32-544".to_string(), "S-1-5-32-545".into()], everyone.to_vec()].concat()),
        ("user".into(), "A standard user".into(), [vec!["S-1-5-32-545".to_string()], everyone.to_vec()].concat()),
    ];
    for service in ["sshd", "gxwid", "resolvd", "pnpd", "atriumd"] {
        let sid = pnp_core::Sid::service(service).to_string();
        out.push((format!("svc:{service}"), format!("The {service} service"), [vec![sid, "S-1-5-6".into(), "S-1-5-19".into()], everyone.to_vec()].concat()));
    }
    out
}

/// The reservation a port takes: the narrowest that covers it, else the
/// default.
pub fn reservation_for<'a>(reservations: &'a [Reservation], protocol: &str, port: u16) -> Option<&'a Reservation> {
    reservations
        .iter()
        .filter(|r| !r.is_default())
        .filter_map(|r| r.covers().filter(|(protos, lo, hi)| protos.iter().any(|p| p == protocol) && *lo <= port && port <= *hi).map(|(_, lo, hi)| (r, hi - lo)))
        .min_by_key(|(_, width)| *width)
        .map(|(r, _)| r)
        .or_else(|| reservations.iter().find(|r| r.is_default()))
}

fn who(m: &Manager, sd: &[u8]) -> String {
    let mut out = String::new();
    for (sid, allows, mask) in machine::grants(sd) {
        if mask & BIND == 0 {
            continue;
        }
        let name = m.config.names.get(&sid).cloned().unwrap_or_else(|| sid.clone());
        let class = if !allows {
            "deny"
        } else if sid == "S-1-1-0" {
            "all"
        } else if sid.starts_with("S-1-5-80-") {
            "svc"
        } else {
            ""
        };
        out += &format!(r#"<span class="{class}">{}{}</span>"#, if allows { "" } else { "Not " }, h(&name));
    }
    if out.is_empty() {
        out = r#"<span>No one</span>"#.into();
    }
    format!(r#"<span class="who">{out}</span>"#)
}

pub fn page(m: &Manager) -> String {
    let may = m.config.may.reservations && m.busy.is_none();
    let off = if may { "" } else { " disabled" };
    let rs = &m.config.reservations;
    // Ports on a log scale: 1 at the left, 65535 at the right.
    let at = |p: u16| (f64::from(p.max(1)).log10() / 65535f64.log10() * 100.0).clamp(0.0, 100.0);
    // The shapes are drawn in SVG, whose attributes the page allows; the
    // labels are placed by whole percent, as classes.
    let mut shapes = String::new();
    let mut labels = String::new();
    let mut lowest_free = 1u16;
    for r in rs.iter().filter(|r| !r.is_default()) {
        let Some((_, lo, hi)) = r.covers() else { continue };
        if lo == hi {
            shapes += &format!(r#"<rect class="pin" x="{:.1}" y="-3" width="3" height="40"><title>{}</title></rect>"#, at(lo) * 10.0 - 1.5, h(&r.selector));
            labels += &format!(r#"<span class="pinlbl at{:.0}">{lo}</span>"#, at(lo));
        } else {
            shapes += &format!(r#"<rect class="range" x="{:.1}" y="0" width="{:.1}" height="34" rx="6"><title>{}</title></rect>"#, at(lo) * 10.0, (at(hi) - at(lo)) * 10.0, h(&r.selector));
            if lo <= 1 {
                lowest_free = lowest_free.max(hi.saturating_add(1));
                labels += &format!(r#"<span class="lbl2 first">{lo}–{hi}: restricted</span>"#);
            }
        }
    }
    labels += &format!(r#"<span class="lbl2 after at{:.0}">Others: the default</span>"#, at(lowest_free));
    let bar = format!(r#"<svg viewBox="0 0 1000 34" preserveAspectRatio="none" aria-hidden="true">{shapes}</svg>{labels}"#);
    let rows: String = rs
        .iter()
        .map(|r| {
            let ports = match r.covers() {
                _ if r.is_default() => "Every other port".to_string(),
                Some((protos, lo, hi)) => format!("{} {}", protos.iter().map(|p| p.to_uppercase()).collect::<Vec<_>>().join(", "), if lo == hi { lo.to_string() } else { format!("{lo}–{hi}") }),
                None => "Can't be read".into(),
            };
            let remove = if r.is_default() { String::new() } else { format!(r#"<button class="x" fx-click="res-remove"{}{off} aria-label="Remove {}">×</button>"#, values(&[("w", &r.selector)]), h(&r.selector)) };
            format!(
                r#"<tr><td class="mono">{}</td><td>{}</td><td>{}</td><td class="w"><button class="btn sm" fx-click="perm"{}>Permissions…</button>{remove}</td></tr>"#,
                if r.is_default() { r#"<b class="plain">Default</b>"#.to_string() } else { h(&r.selector) },
                h(&ports),
                who(m, &r.sd),
                values(&[("w", &r.selector)])
            )
        })
        .collect();
    let answer = match &m.port_check {
        None => String::new(),
        Some(check) => match check.port.parse::<u16>() {
            Ok(port) if port >= 1 => {
                let all = principals();
                let (label, sids) = all.iter().find(|(k, _, _)| *k == check.who).map(|(_, l, s)| (l.clone(), s.clone())).unwrap_or_default();
                match reservation_for(rs, &check.protocol, port) {
                    Some(r) => {
                        let ok = machine::granted(&r.sd, &sids, BIND);
                        format!(
                            r#"<div class="answerline {}"><span class="big">{}</span><span>{} on {}/{port}. {}: {}</span></div>"#,
                            if ok { "yes" } else { "no" },
                            if ok { "Can listen" } else { "Can't listen" },
                            h(&label),
                            h(&check.protocol),
                            if r.is_default() { "No reservation covers it, so the default applies".to_string() } else { format!(r#"Reservation <span class="mono">{}</span> applies"#, h(&r.selector)) },
                            who(m, &r.sd)
                        )
                    }
                    None => r#"<div class="answerline yes"><span class="big">Can listen</span><span>No reservation covers it, and there is no default.</span></div>"#.into(),
                }
            }
            _ => r#"<div class="answerline no"><span class="big">Give a port from 1 to 65535</span></div>"#.into(),
        },
    };
    let people: Vec<(String, String)> = principals().into_iter().map(|(k, l, _)| (k, l)).collect();
    format!(
        r#"{}{}<div class="sect"><div class="panel pad"><div class="portbar">{bar}</div><div class="portaxis"><span>1</span><span>10</span><span>100</span><span>1,000</span><span>10,000</span><span>65,535</span></div></div></div><div class="sect"><div class="panel scroll"><table class="tbl"><thead><tr><th>Reservation</th><th>Ports</th><th>Who can listen</th><th></th></tr></thead><tbody>{rows}</tbody></table></div><div class="checkrow gap-top8"><input class="inp mono w180" name="res-new" placeholder="tcp:8443" autocomplete="off"{off}><button class="btn sm" fx-click="perm"{}{off}>{}Add reservation</button></div></div><div class="sect"><h2>Check a port</h2><div class="panel pad"><div class="checkrow"><label class="fld"><span>Port</span><input class="inp mono w100" name="pc-port" inputmode="numeric" autocomplete="off"></label><label class="fld"><span>Protocol</span>{}</label><label class="fld"><span>Program running as</span>{}</label><button class="btn primary" fx-click="port-check">Check</button></div>{answer}</div><div class="footnote">A reservation says who may listen. Who may connect is the firewall's to say: see <button class="btn ghost sm inline" fx-click="section"{}>Exposure</button>.</div></div>"#,
        phead("Port reservations", "Who may listen on a port. Each port uses its narrowest reservation; a port without one uses the default.", ""),
        locked(m.config.may.reservations, LOCKED),
        values(&[("w", "new-reservation")]),
        svg("plus"),
        select("pc-proto", &[("tcp".into(), "TCP".into()), ("udp".into(), "UDP".into())], true),
        select("pc-who", &people, true),
        values(&[("section", "exposure")])
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sd(sddl: &str) -> Vec<u8> {
        peios::security::sddl::parse(sddl).map(|s| s.as_bytes().to_vec()).unwrap_or_default()
    }

    #[test]
    fn a_port_takes_its_narrowest_reservation() {
        let rs = vec![
            Reservation { selector: "@".into(), sd: Vec::new() },
            Reservation { selector: "tcp,udp:1-1023".into(), sd: Vec::new() },
            Reservation { selector: "tcp:22".into(), sd: Vec::new() },
        ];
        assert_eq!(reservation_for(&rs, "tcp", 22).map(|r| r.selector.as_str()), Some("tcp:22"));
        assert_eq!(reservation_for(&rs, "udp", 22).map(|r| r.selector.as_str()), Some("tcp,udp:1-1023"));
        assert_eq!(reservation_for(&rs, "tcp", 8080).map(|r| r.selector.as_str()), Some("@"));
    }

    #[test]
    fn who_may_listen_is_read_from_the_access_list() {
        let ssh = sd("O:SYG:SYD:(A;;0x1;;;SY)(A;;0x1;;;S-1-5-80-1-2-3-4-5)");
        assert!(machine::granted(&ssh, &["S-1-5-18".into()], BIND));
        assert!(!machine::granted(&ssh, &["S-1-5-32-544".into(), "S-1-1-0".into()], BIND));
        let open = sd("O:SYG:SYD:(D;;0x1;;;BG)(A;;0x1;;;WD)");
        assert!(machine::granted(&open, &["S-1-1-0".into()], BIND));
        assert!(!machine::granted(&open, &["S-1-5-32-546".into(), "S-1-1-0".into()], BIND));
    }
}
