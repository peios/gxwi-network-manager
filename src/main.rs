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

mod engine;
mod live;
mod machine;
mod registry;
mod rules;
mod vocab;

fn main() {}
