//! Policy: which authentication methods are acceptable for which PAM service,
//! user and group (PLAN.md §6).
//!
//! Policy files are TOML. They are merged in order: built-in defaults, then
//! `/usr/share/tuxhello/policy.d/*.toml` (vendor), then
//! `/etc/tuxhello/policy.d/*.toml` (admin). Within a directory, files are read
//! in lexical order. A later file overrides individual fields of an earlier
//! one.
//!
//! ```toml
//! [class.elevate]                       # sudo, su, polkit, pkexec
//! require = { any = ["key", "fingerprint", { all = ["voice", "pin"] }] }
//! min_assurance = 3
//! timeout_s = 15
//!
//! [service."my-app"]                    # map a PAM service to a class...
//! class = "elevate"
//! timeout_s = 30                        # ...and optionally override fields
//!
//! [group.wheel.class.elevate]           # stricter rules for a group
//! require = { all = ["fingerprint", "key"] }
//!
//! [user.alice.class.unlock]             # or for one user
//! require = "key"
//! ```
//!
//! Precedence for one request: class < service < group < user. When a user
//! is in several groups with overrides, groups are applied in name order.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

/// Method names the daemon knows. Unknown names in a policy are an error.
pub const KNOWN_METHODS: &[&str] = &["pin", "key", "fingerprint", "face", "voice", "stub"];

/// Highest assurance level (PLAN.md §5).
pub const MAX_ASSURANCE: u32 = 4;

/// Built-in defaults. Kept as TOML so that they are documented in the same
/// language admins use, and tested by the same parser.
pub const DEFAULT_POLICY: &str = r#"
# Login screens: first sign-in of a session.
[class.login]
require = { any = ["fingerprint", "face", "key", "pin"] }
min_assurance = 2
timeout_s = 10

# Screen lockers: low risk, the session is already open.
[class.unlock]
require = { any = ["fingerprint", "face", "key", "pin", "voice"] }
min_assurance = 1
timeout_s = 8

# Privilege elevation: sudo, su, polkit.
[class.elevate]
require = { any = ["key", "fingerprint", "face", "pin", { all = ["voice", "pin"] }] }
min_assurance = 2
timeout_s = 15

# Anything else.
[class.other]
require = { any = ["key", "fingerprint", "face", "pin"] }
min_assurance = 2
timeout_s = 10
"#;

/// Built-in PAM service → class mapping. Policy files can add to or override it
/// with `[service."name"] class = "..."`.
const SERVICE_CLASSES: &[(&str, &str)] = &[
    // elevate
    ("sudo", "elevate"),
    ("sudo-i", "elevate"),
    ("su", "elevate"),
    ("su-l", "elevate"),
    ("polkit-1", "elevate"),
    ("pkexec", "elevate"),
    ("doas", "elevate"),
    ("run0", "elevate"),
    // login
    ("login", "login"),
    ("gdm-password", "login"),
    ("gdm-fingerprint", "login"),
    ("sddm", "login"),
    ("lightdm", "login"),
    ("lightdm-greeter", "login"),
    ("greetd", "login"),
    ("ly", "login"),
    ("lemurs", "login"),
    ("emptty", "login"),
    // unlock
    ("swaylock", "unlock"),
    ("hyprlock", "unlock"),
    ("i3lock", "unlock"),
    ("gtklock", "unlock"),
    ("waylock", "unlock"),
    ("kde", "unlock"),
    ("kde-fingerprint", "unlock"),
    ("xscreensaver", "unlock"),
    ("xsecurelock", "unlock"),
    ("light-locker", "unlock"),
    ("physlock", "unlock"),
];

/// A requirement tree: a single method, or any/all of sub-requirements.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Requirement {
    Method(String),
    Any { any: Vec<Requirement> },
    All { all: Vec<Requirement> },
}

impl Requirement {
    /// All method names that appear in the tree.
    pub fn methods(&self) -> BTreeSet<&str> {
        let mut out = BTreeSet::new();
        self.collect(&mut out);
        out
    }

    fn collect<'a>(&'a self, out: &mut BTreeSet<&'a str>) {
        match self {
            Requirement::Method(m) => {
                out.insert(m.as_str());
            }
            Requirement::Any { any: v } | Requirement::All { all: v } => {
                v.iter().for_each(|r| r.collect(out))
            }
        }
    }

    /// Assurance achieved given the methods that succeeded (with their
    /// assurance), or `None` if the requirement is not met.
    ///
    /// `any` takes the strongest satisfied branch; `all` adds its members'
    /// assurances (capped at [`MAX_ASSURANCE`]), so two weak factors together
    /// can meet a bar neither meets alone.
    pub fn evaluate(&self, ok: &dyn Fn(&str) -> Option<u32>) -> Option<u32> {
        match self {
            Requirement::Method(m) => ok(m),
            Requirement::Any { any } => any.iter().filter_map(|r| r.evaluate(ok)).max(),
            Requirement::All { all } => {
                if all.is_empty() {
                    return None;
                }
                let mut sum = 0u32;
                for r in all {
                    sum = sum.saturating_add(r.evaluate(ok)?);
                }
                Some(sum.min(MAX_ASSURANCE))
            }
        }
    }

    fn validate(&self, at: &str) -> Result<(), PolicyError> {
        match self {
            Requirement::Method(m) if !KNOWN_METHODS.contains(&m.as_str()) => {
                Err(PolicyError::Invalid(format!("{at}: unknown method {m:?}")))
            }
            Requirement::Method(_) => Ok(()),
            Requirement::Any { any: v } | Requirement::All { all: v } => {
                if v.is_empty() {
                    return Err(PolicyError::Invalid(format!("{at}: empty any/all list")));
                }
                v.iter().try_for_each(|r| r.validate(at))
            }
        }
    }
}

impl fmt::Display for Requirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let list = |f: &mut fmt::Formatter<'_>, v: &[Requirement], sep: &str| {
            write!(f, "(")?;
            for (i, r) in v.iter().enumerate() {
                if i > 0 {
                    write!(f, " {sep} ")?;
                }
                write!(f, "{r}")?;
            }
            write!(f, ")")
        };
        match self {
            Requirement::Method(m) => write!(f, "{m}"),
            Requirement::Any { any } => list(f, any, "or"),
            Requirement::All { all } => list(f, all, "and"),
        }
    }
}

/// Fields that can be set per class, and overridden per service/group/user.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub require: Option<Requirement>,
    pub min_assurance: Option<u32>,
    pub timeout_s: Option<u64>,
}

impl Rule {
    fn overlay(&mut self, other: &Rule) {
        if other.require.is_some() {
            self.require = other.require.clone();
        }
        if other.min_assurance.is_some() {
            self.min_assurance = other.min_assurance;
        }
        if other.timeout_s.is_some() {
            self.timeout_s = other.timeout_s;
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceRule {
    class: Option<String>,
    require: Option<Requirement>,
    min_assurance: Option<u32>,
    timeout_s: Option<u64>,
}

impl ServiceRule {
    fn rule(&self) -> Rule {
        Rule {
            require: self.require.clone(),
            min_assurance: self.min_assurance,
            timeout_s: self.timeout_s,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Overrides {
    #[serde(default)]
    class: BTreeMap<String, Rule>,
}

/// One parsed policy file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    class: BTreeMap<String, Rule>,
    #[serde(default)]
    service: BTreeMap<String, ServiceRule>,
    #[serde(default)]
    group: BTreeMap<String, Overrides>,
    #[serde(default)]
    user: BTreeMap<String, Overrides>,
}

#[derive(Debug)]
pub enum PolicyError {
    Io(PathBuf, std::io::Error),
    Parse(String, toml::de::Error),
    Invalid(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::Io(p, e) => write!(f, "{}: {e}", p.display()),
            PolicyError::Parse(src, e) => write!(f, "{src}: {e}"),
            PolicyError::Invalid(m) => write!(f, "invalid policy: {m}"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// The merged policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    merged: PolicyFile,
}

/// The policy that applies to one authentication request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    pub class: String,
    pub require: Requirement,
    pub min_assurance: u32,
    pub timeout: Duration,
}

impl Effective {
    /// Assurance reached with the given successful methods, if it meets
    /// `min_assurance`.
    pub fn satisfied(&self, ok: &dyn Fn(&str) -> Option<u32>) -> Option<u32> {
        self.require
            .evaluate(ok)
            .filter(|&a| a >= self.min_assurance)
    }
}

impl Policy {
    /// Built-in defaults only.
    pub fn builtin() -> Self {
        Self::from_sources(&[("<built-in>", DEFAULT_POLICY)]).expect("built-in policy is valid")
    }

    /// Defaults merged with `(name, toml)` sources, in order.
    pub fn from_sources(sources: &[(&str, &str)]) -> Result<Self, PolicyError> {
        let mut merged = PolicyFile::default();
        for (name, text) in sources {
            let file: PolicyFile =
                toml::from_str(text).map_err(|e| PolicyError::Parse(name.to_string(), e))?;
            merge(&mut merged, file);
        }
        let p = Policy { merged };
        p.validate()?;
        Ok(p)
    }

    /// Built-in defaults merged with every `*.toml` in `dirs`, in order.
    /// Missing directories are skipped.
    pub fn load(dirs: &[&Path]) -> Result<Self, PolicyError> {
        let mut texts = vec![("<built-in>".to_string(), DEFAULT_POLICY.to_string())];
        for dir in dirs {
            let entries = match std::fs::read_dir(dir) {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(PolicyError::Io(dir.to_path_buf(), e)),
            };
            let mut files: Vec<PathBuf> = entries
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "toml"))
                .collect();
            files.sort();
            for f in files {
                let text =
                    std::fs::read_to_string(&f).map_err(|e| PolicyError::Io(f.clone(), e))?;
                texts.push((f.display().to_string(), text));
            }
        }
        let refs: Vec<(&str, &str)> = texts
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        Self::from_sources(&refs)
    }

    fn validate(&self) -> Result<(), PolicyError> {
        let check = |at: String, r: &Rule| -> Result<(), PolicyError> {
            if let Some(req) = &r.require {
                req.validate(&at)?;
            }
            if let Some(a) = r.min_assurance {
                if a > MAX_ASSURANCE {
                    return Err(PolicyError::Invalid(format!(
                        "{at}: min_assurance {a} is above the maximum {MAX_ASSURANCE}"
                    )));
                }
            }
            if r.timeout_s == Some(0) {
                return Err(PolicyError::Invalid(format!("{at}: timeout_s must be > 0")));
            }
            Ok(())
        };
        let m = &self.merged;
        for (name, r) in &m.class {
            check(format!("class.{name}"), r)?;
            if r.require.is_none() {
                return Err(PolicyError::Invalid(format!(
                    "class.{name}: missing require"
                )));
            }
        }
        for (name, s) in &m.service {
            check(format!("service.{name}"), &s.rule())?;
            if let Some(c) = &s.class {
                if !m.class.contains_key(c) {
                    return Err(PolicyError::Invalid(format!(
                        "service.{name}: unknown class {c:?}"
                    )));
                }
            }
        }
        for (kind, map) in [("group", &m.group), ("user", &m.user)] {
            for (who, o) in map {
                for (c, r) in &o.class {
                    if !m.class.contains_key(c) {
                        return Err(PolicyError::Invalid(format!(
                            "{kind}.{who}.class.{c}: unknown class"
                        )));
                    }
                    check(format!("{kind}.{who}.class.{c}"), r)?;
                }
            }
        }
        if !m.class.contains_key("other") {
            return Err(PolicyError::Invalid("class.other must exist".into()));
        }
        Ok(())
    }

    /// Class a PAM service belongs to.
    pub fn class_of(&self, service: &str) -> String {
        if let Some(c) = self
            .merged
            .service
            .get(service)
            .and_then(|s| s.class.clone())
        {
            return c;
        }
        SERVICE_CLASSES
            .iter()
            .find(|(s, _)| *s == service)
            .map(|(_, c)| c.to_string())
            .unwrap_or_else(|| "other".to_string())
    }

    /// Resolves the policy for one request.
    pub fn resolve(&self, service: &str, user: &str, groups: &[String]) -> Effective {
        let m = &self.merged;
        let class = self.class_of(service);
        let mut rule = m.class.get(&class).cloned().unwrap_or_default();
        if let Some(s) = m.service.get(service) {
            rule.overlay(&s.rule());
        }
        let mut sorted: Vec<&String> = groups.iter().collect();
        sorted.sort();
        sorted.dedup();
        for g in sorted {
            if let Some(r) = m.group.get(g.as_str()).and_then(|o| o.class.get(&class)) {
                rule.overlay(r);
            }
        }
        if let Some(r) = m.user.get(user).and_then(|o| o.class.get(&class)) {
            rule.overlay(r);
        }
        Effective {
            class,
            // `validate` guarantees every class has a requirement.
            require: rule
                .require
                .unwrap_or_else(|| Requirement::Any { any: Vec::new() }),
            min_assurance: rule.min_assurance.unwrap_or(2),
            timeout: Duration::from_secs(rule.timeout_s.unwrap_or(10)),
        }
    }
}

fn merge(into: &mut PolicyFile, from: PolicyFile) {
    for (k, r) in from.class {
        into.class.entry(k).or_default().overlay(&r);
    }
    for (k, s) in from.service {
        let e = into.service.entry(k).or_default();
        if s.class.is_some() {
            e.class = s.class.clone();
        }
        let mut r = e.rule();
        r.overlay(&s.rule());
        e.require = r.require;
        e.min_assurance = r.min_assurance;
        e.timeout_s = r.timeout_s;
    }
    for (kind_into, kind_from) in [(&mut into.group, from.group), (&mut into.user, from.user)] {
        for (who, o) in kind_from {
            let e = kind_into.entry(who).or_default();
            for (c, r) in o.class {
                e.class.entry(c).or_default().overlay(&r);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_with<'a>(methods: &'a [(&'static str, u32)]) -> impl Fn(&str) -> Option<u32> + 'a {
        move |m| methods.iter().find(|(n, _)| *n == m).map(|(_, a)| *a)
    }

    #[test]
    fn builtin_parses_and_validates() {
        let p = Policy::builtin();
        for c in ["login", "unlock", "elevate", "other"] {
            assert!(p.merged.class.contains_key(c), "{c}");
        }
    }

    #[test]
    fn service_mapping() {
        let p = Policy::builtin();
        assert_eq!(p.class_of("sudo"), "elevate");
        assert_eq!(p.class_of("swaylock"), "unlock");
        assert_eq!(p.class_of("gdm-password"), "login");
        assert_eq!(p.class_of("something-new"), "other");
    }

    #[test]
    fn any_takes_strongest_branch() {
        let r = Requirement::Any {
            any: vec![
                Requirement::Method("pin".into()),
                Requirement::Method("key".into()),
            ],
        };
        assert_eq!(r.evaluate(&ok_with(&[("pin", 2), ("key", 4)])), Some(4));
        assert_eq!(r.evaluate(&ok_with(&[("pin", 2)])), Some(2));
        assert_eq!(r.evaluate(&ok_with(&[])), None);
    }

    #[test]
    fn all_requires_every_member_and_adds_up() {
        let r = Requirement::All {
            all: vec![
                Requirement::Method("voice".into()),
                Requirement::Method("pin".into()),
            ],
        };
        assert_eq!(r.evaluate(&ok_with(&[("voice", 1)])), None);
        assert_eq!(r.evaluate(&ok_with(&[("voice", 1), ("pin", 2)])), Some(3));
        assert_eq!(
            r.evaluate(&ok_with(&[("voice", 3), ("pin", 3)])),
            Some(MAX_ASSURANCE)
        );
    }

    #[test]
    fn min_assurance_is_enforced() {
        let p = Policy::from_sources(&[
            ("<built-in>", DEFAULT_POLICY),
            ("t", "[class.elevate]\nmin_assurance = 3\n"),
        ])
        .unwrap();
        let e = p.resolve("sudo", "alice", &[]);
        assert_eq!(e.satisfied(&ok_with(&[("pin", 2)])), None);
        assert_eq!(e.satisfied(&ok_with(&[("key", 4)])), Some(4));
        // voice + software PIN together reach 3.
        assert_eq!(e.satisfied(&ok_with(&[("voice", 1), ("pin", 2)])), Some(3));
    }

    #[test]
    fn requirement_syntax_variants() {
        let p = Policy::from_sources(&[
            ("<built-in>", DEFAULT_POLICY),
            (
                "t",
                r#"
                [class.unlock]
                require = "key"
                [class.elevate]
                require = { all = ["fingerprint", { any = ["key", "pin"] }] }
                "#,
            ),
        ])
        .unwrap();
        assert_eq!(
            p.resolve("swaylock", "a", &[]).require,
            Requirement::Method("key".into())
        );
        let e = p.resolve("sudo", "a", &[]);
        assert_eq!(e.require.to_string(), "(fingerprint and (key or pin))");
        assert_eq!(
            e.require.methods().into_iter().collect::<Vec<_>>(),
            vec!["fingerprint", "key", "pin"]
        );
    }

    #[test]
    fn precedence_class_service_group_user() {
        let p = Policy::from_sources(&[
            ("<built-in>", DEFAULT_POLICY),
            (
                "t",
                r#"
                [service.sudo]
                timeout_s = 30
                [group.wheel.class.elevate]
                require = { all = ["fingerprint", "key"] }
                min_assurance = 4
                [user.bob.class.elevate]
                require = "key"
                "#,
            ),
        ])
        .unwrap();
        let plain = p.resolve("sudo", "alice", &[]);
        assert_eq!(plain.timeout, Duration::from_secs(30));
        assert_eq!(plain.min_assurance, 2);

        let wheel = p.resolve("sudo", "alice", &["wheel".into()]);
        assert_eq!(wheel.require.to_string(), "(fingerprint and key)");
        assert_eq!(wheel.min_assurance, 4);
        assert_eq!(wheel.timeout, Duration::from_secs(30));

        let bob = p.resolve("sudo", "bob", &["wheel".into()]);
        assert_eq!(bob.require, Requirement::Method("key".into()));
        assert_eq!(
            bob.min_assurance, 4,
            "user override keeps group fields it doesn't set"
        );
    }

    #[test]
    fn later_files_override_fields_not_whole_classes() {
        let p = Policy::from_sources(&[
            ("<built-in>", DEFAULT_POLICY),
            ("a", "[class.unlock]\ntimeout_s = 3\n"),
        ])
        .unwrap();
        let e = p.resolve("swaylock", "x", &[]);
        assert_eq!(e.timeout, Duration::from_secs(3));
        assert_eq!(e.min_assurance, 1);
        assert!(e.require.methods().contains("fingerprint"));
    }

    #[test]
    fn service_can_be_mapped_to_a_class() {
        let p = Policy::from_sources(&[
            ("<built-in>", DEFAULT_POLICY),
            ("a", "[service.my-app]\nclass = \"elevate\"\n"),
        ])
        .unwrap();
        assert_eq!(p.resolve("my-app", "x", &[]).class, "elevate");
    }

    #[test]
    fn rejects_invalid_policies() {
        for bad in [
            "[class.elevate]\nrequire = \"retina\"\n",
            "[class.elevate]\nrequire = { any = [] }\n",
            "[class.elevate]\nmin_assurance = 9\n",
            "[class.elevate]\ntimeout_s = 0\n",
            "[class.elevate]\nbogus = 1\n",
            "[class.newclass]\ntimeout_s = 5\n",
            "[service.x]\nclass = \"nope\"\n",
            "[group.wheel.class.nope]\nrequire = \"key\"\n",
            "[class.elevate]\nrequire = 5\n",
        ] {
            let r = Policy::from_sources(&[("<built-in>", DEFAULT_POLICY), ("t", bad)]);
            assert!(r.is_err(), "accepted: {bad}");
        }
    }

    #[test]
    fn load_reads_dirs_in_order_and_skips_missing() {
        let base =
            std::env::temp_dir().join(format!("tuxhello-policy-test-{}", std::process::id()));
        let vendor = base.join("vendor");
        let admin = base.join("admin");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::create_dir_all(&admin).unwrap();
        std::fs::write(vendor.join("10-a.toml"), "[class.unlock]\ntimeout_s = 4\n").unwrap();
        std::fs::write(vendor.join("20-b.toml"), "[class.unlock]\ntimeout_s = 5\n").unwrap();
        std::fs::write(
            admin.join("50-admin.toml"),
            "[class.unlock]\nmin_assurance = 3\n",
        )
        .unwrap();
        std::fs::write(admin.join("ignored.txt"), "not toml").unwrap();
        let p = Policy::load(&[&vendor, &admin, &base.join("missing")]).unwrap();
        let e = p.resolve("swaylock", "x", &[]);
        assert_eq!(e.timeout, Duration::from_secs(5));
        assert_eq!(e.min_assurance, 3);
        std::fs::remove_dir_all(&base).unwrap();
    }
}
