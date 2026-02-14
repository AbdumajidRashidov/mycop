pub mod json;
pub mod sarif;
pub mod terminal;

use crate::rules::matcher::Finding;
use anyhow::Result;
use std::collections::HashMap;

pub trait Reporter {
    fn report(&self, findings: &[Finding], ai_results: &HashMap<usize, String>) -> Result<String>;
}
