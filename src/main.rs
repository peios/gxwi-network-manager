//! Network Manager: this machine's interfaces, the networks they stand on,
//! the profiles and rules that decide how, name resolution, the firewall,
//! and who may listen on a port.
//!
//! What it shows is read as the person: netd's and resolvd's status, the
//! registry under `Machine\System\Network`, and the kernel's own view of
//! links and routes. What it changes is written to the registry as the
//! person, checked first by the machine's own laws (`engine`). The
//! firewall's live state, its connections, counts and verdicts, has no
//! interface a program may read yet: until it does, it is example data,
//! behind one seam (`live`), and said to be.

use libgxwi::App;

mod engine;
mod live;
mod machine;
mod manager;
mod pages;
mod registry;
mod rules;
mod ui;
mod vocab;

use manager::Manager;

// What this program looks like, to whatever lists it. The icon itself is
// `gxwi-network-manager.svg` at the repo root, installed as the base theme's.
libgxwi::icon!(b"dev.peios.gxwi-network-manager");

fn main() {
    if std::env::args().nth(1).is_some() {
        eprintln!("gxwi-network-manager: usage: gxwi-network-manager (given {:?})", std::env::args().skip(1).collect::<Vec<_>>());
        std::process::exit(64);
    }
    let mut app = match App::connect() {
        Ok(app) => app,
        Err(e) => {
            eprintln!("gxwi-network-manager: no desktop to open on: {e}");
            std::process::exit(1);
        }
    };
    libgxwi::settings::stylesheet(&mut app);
    app.stylesheet("/gxwi-network-manager.css", include_str!("gxwi-network-manager.css"));
    let window = app.live("Network Manager", Manager::new());
    let aside = std::sync::Arc::downgrade(&window);
    window.update(|manager, fields| {
        manager.window = aside;
        fields.set("lk-q", "peios.org");
        fields.set("lk-t", "A");
        fields.set("pc-port", "22");
        fields.set("pc-proto", "tcp");
        fields.set("pc-who", "admin");
        manager.reread();
        manager.watch();
    });
    if let Err(e) = app.run() {
        eprintln!("gxwi-network-manager: {e}");
        std::process::exit(1);
    }
}
