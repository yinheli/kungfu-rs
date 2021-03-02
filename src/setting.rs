use std::sync::Arc;

use config::{Config, ConfigError};

#[derive(Debug, serde_derive::Deserialize)]
pub struct Setting {
    pub dns_port: i64,
    pub dns_ttl: i64,
    pub dns_upstream: Vec<String>,
    pub dns_fallback: Vec<String>,
    pub metrics: String,
    pub network: Vec<String>,
    pub proxy: Vec<Proxy>,
    pub hosts: String,
    pub rules: Vec<Rule>,
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct Proxy {
    pub name: String,
    pub values: Vec<String>,
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct Rule {
    #[serde(rename = "type")]
    pub rule_type: RuleType,
    pub target: String,
    pub values: Vec<String>,
}

#[derive(Debug, PartialEq)]
pub enum RuleType {
    Route,
    Domain,
    DnsCidrArea,
    DnsCidr,
    Unknown(String),
}

impl<'de> serde::de::Deserialize<'de> for RuleType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?.to_lowercase();

        let t = match s.as_str() {
            "route" => RuleType::Route,
            "domain" => RuleType::Domain,
            "dnscidr" => RuleType::DnsCidr,
            "dnscidrarea" => RuleType::DnsCidrArea,
            s => RuleType::Unknown(s.to_string()),
        };

        Ok(t)
    }
}

impl Setting {
    pub fn load(file: &str) -> Result<Arc<Self>, ConfigError> {
        let mut c = Config::new();
        Self::config_default(&mut c)?;

        // merge local files
        if file != "" {
            debug!("loading local config file: {}", file);
            c.merge(config::File::with_name(file))?;
        }

        match c.try_into() {
            Ok(setting) => Ok(Arc::new(setting)),
            Err(e) => Err(e),
        }
    }

    fn config_default(c: &mut Config) -> Result<(), ConfigError> {
        c.set_default("dns_port", 53)?;
        c.set_default("dns_ttl", 10)?;
        c.set_default("dns_upstream", vec!["1.2.4.8", "114.114.114.114"])?;
        c.set_default("metrics", "0.0.0.0:3001")?;
        c.set_default("network", vec!["10.88.0.1/16"])?;
        c.set_default("hosts", "")?;
        Ok(())
    }
}
