#![forbid(unsafe_code)]

//! CRAP score per function: `complexity² × (1 − coverage)³ + complexity`.
//!
//! Complexity is the cyclomatic complexity of the function body, computed from the syntax tree.
//! Coverage is the share of code regions executed, from the `cargo llvm-cov --json` export.
//! Test code (`#[cfg(test)]` items, `#[test]` functions) is not scored.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use quote::ToTokens;
use serde_json::Value;
use syn::visit::{self, Visit};

/// A function that can be scored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    pub name: String,
    pub file: PathBuf,
    /// 1-based line of the first token (visibility, `fn`, ...) and of the opening brace.
    pub first_line: usize,
    pub body_line: usize,
    pub complexity: u32,
}

/// A function with its coverage and score.
#[derive(Debug, Clone, PartialEq)]
pub struct Scored {
    pub function: Function,
    /// Share of code regions executed, 0.0 to 1.0.
    pub coverage: f64,
    pub crap: f64,
}

impl fmt::Display for Scored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} {} complexity {} coverage {:.0}% CRAP {:.1}",
            self.function.file.display(),
            self.function.first_line,
            self.function.name,
            self.function.complexity,
            self.coverage * 100.0,
            self.crap
        )
    }
}

/// The CRAP score of a function with the given complexity and coverage (0.0 to 1.0).
#[must_use]
pub fn crap_score(complexity: u32, coverage: f64) -> f64 {
    let c = f64::from(complexity);
    c * c * (1.0 - coverage).powi(3) + c
}

/// Cyclomatic complexity of a function body: one, plus one for every decision point.
#[must_use]
pub fn complexity(block: &syn::Block) -> u32 {
    struct Counter(u32);
    impl<'ast> Visit<'ast> for Counter {
        fn visit_expr(&mut self, e: &'ast syn::Expr) {
            match e {
                syn::Expr::If(_)
                | syn::Expr::While(_)
                | syn::Expr::ForLoop(_)
                | syn::Expr::Loop(_)
                | syn::Expr::Try(_) => self.0 += 1,
                syn::Expr::Match(m) => {
                    let arms = u32::try_from(m.arms.len()).unwrap_or(u32::MAX);
                    self.0 = self.0.saturating_add(arms.saturating_sub(1));
                }
                syn::Expr::Binary(b) if matches!(b.op, syn::BinOp::And(_) | syn::BinOp::Or(_)) => {
                    self.0 += 1;
                }
                _ => {}
            }
            visit::visit_expr(self, e);
        }

        fn visit_pat_guard(&mut self, g: &'ast syn::PatGuard) {
            self.0 += 1;
            visit::visit_pat_guard(self, g);
        }

        fn visit_local(&mut self, local: &'ast syn::Local) {
            if local.init.as_ref().is_some_and(|i| i.diverge.is_some()) {
                self.0 += 1;
            }
            visit::visit_local(self, local);
        }

        // Nested functions are scored on their own.
        fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
        fn visit_impl_item_fn(&mut self, _: &'ast syn::ImplItemFn) {}
    }
    let mut counter = Counter(1);
    counter.visit_block(block);
    counter.0
}

fn is_test_attr(attr: &syn::Attribute) -> bool {
    let path = attr.path();
    if path.is_ident("test") {
        return true;
    }
    path.is_ident("cfg")
        && attr
            .to_token_stream()
            .to_string()
            .replace(' ', "")
            .contains("(test)")
}

struct Collector<'a> {
    file: &'a Path,
    out: Vec<Function>,
}

impl Collector<'_> {
    fn add(
        &mut self,
        attrs: &[syn::Attribute],
        vis: &syn::Visibility,
        sig: &syn::Signature,
        block: &syn::Block,
    ) {
        if attrs.iter().any(is_test_attr) {
            return;
        }
        let first = vis
            .to_token_stream()
            .into_iter()
            .chain(sig.to_token_stream())
            .next()
            .map_or(sig.fn_token.span.start(), |t| t.span().start());
        self.out.push(Function {
            name: sig.ident.to_string(),
            file: self.file.to_path_buf(),
            first_line: first.line,
            body_line: block.brace_token.span.open().start().line,
            complexity: complexity(block),
        });
    }
}

impl<'ast> Visit<'ast> for Collector<'_> {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        self.add(&f.attrs, &f.vis, &f.sig, &f.block);
        visit::visit_item_fn(self, f);
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        self.add(&f.attrs, &f.vis, &f.sig, &f.block);
        visit::visit_impl_item_fn(self, f);
    }

    fn visit_trait_item_fn(&mut self, f: &'ast syn::TraitItemFn) {
        if let Some(block) = &f.default {
            self.add(&f.attrs, &syn::Visibility::Inherited, &f.sig, block);
        }
        visit::visit_trait_item_fn(self, f);
    }

    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        if !m.attrs.iter().any(is_test_attr) {
            visit::visit_item_mod(self, m);
        }
    }
}

/// The functions of one Rust source file.
///
/// # Errors
/// When the source does not parse.
pub fn functions_in(file: &Path, source: &str) -> Result<Vec<Function>, syn::Error> {
    let ast = syn::parse_file(source)?;
    let mut collector = Collector {
        file,
        out: Vec::new(),
    };
    collector.visit_file(&ast);
    Ok(collector.out)
}

/// Code regions of one instrumented function: where it starts and how many ran.
#[derive(Debug, Clone, PartialEq)]
pub struct Instance {
    pub file: PathBuf,
    pub start: (usize, usize),
    pub covered: u32,
    pub total: u32,
}

/// The instrumented functions of a `cargo llvm-cov --json` export.
///
/// # Errors
/// When the document does not have the shape of an export.
pub fn instances(export: &str) -> Result<Vec<Instance>, String> {
    let doc: Value = serde_json::from_str(export).map_err(|e| e.to_string())?;
    let functions = doc
        .pointer("/data/0/functions")
        .and_then(Value::as_array)
        .ok_or("no data[0].functions in the export")?;
    let mut out = Vec::new();
    for f in functions {
        let files = f
            .get("filenames")
            .and_then(Value::as_array)
            .ok_or("function without filenames")?;
        let Some(file) = files.first().and_then(Value::as_str) else {
            continue;
        };
        let regions = f
            .get("regions")
            .and_then(Value::as_array)
            .ok_or("function without regions")?;
        let mut start = None;
        let (mut covered, mut total) = (0, 0);
        for r in regions {
            let r: Vec<u64> = r
                .as_array()
                .ok_or("region is not an array")?
                .iter()
                .filter_map(Value::as_u64)
                .collect();
            // [line, col, end line, end col, count, file id, expanded file id, kind]
            let [line, col, _, _, count, file_id, expanded, kind] = r[..] else {
                return Err("region has the wrong shape".into());
            };
            if kind != 0 || file_id != 0 || expanded != 0 {
                continue;
            }
            let pos = (
                usize::try_from(line).map_err(|e| e.to_string())?,
                usize::try_from(col).map_err(|e| e.to_string())?,
            );
            start = Some(start.map_or(pos, |s: (usize, usize)| s.min(pos)));
            total += 1;
            covered += u32::from(count > 0);
        }
        if let Some(start) = start {
            out.push(Instance {
                file: PathBuf::from(file),
                start,
                covered,
                total,
            });
        }
    }
    Ok(out)
}

/// Scores each function. An instantiation is matched by file and by the first region starting
/// between the function's first token and its opening brace; generic functions have one
/// instantiation per type and score by the best. A function with no instantiation (never compiled
/// into a test binary) has coverage 0.
#[must_use]
pub fn score(functions: Vec<Function>, instances: &[Instance]) -> Vec<Scored> {
    let mut by_file: BTreeMap<&Path, Vec<&Instance>> = BTreeMap::new();
    for i in instances {
        by_file.entry(i.file.as_path()).or_default().push(i);
    }
    functions
        .into_iter()
        .map(|function| {
            let candidates: Vec<&Instance> = by_file
                .iter()
                .filter(|(path, _)| path.ends_with(&function.file))
                .flat_map(|(_, v)| v.iter().copied())
                .filter(|i| (function.first_line..=function.body_line).contains(&i.start.0))
                .collect();
            let first = candidates.iter().map(|i| i.start).min();
            let coverage = candidates
                .iter()
                .filter(|i| Some(i.start) == first)
                .filter(|i| i.total > 0)
                .map(|i| f64::from(i.covered) / f64::from(i.total))
                .fold(0.0, f64::max);
            let crap = crap_score(function.complexity, coverage);
            Scored {
                function,
                coverage,
                crap,
            }
        })
        .collect()
}

/// The scored functions whose CRAP score is above `threshold`, worst first.
#[must_use]
pub fn offenders(scored: &[Scored], threshold: f64) -> Vec<&Scored> {
    let mut bad: Vec<&Scored> = scored.iter().filter(|s| s.crap > threshold).collect();
    bad.sort_by(|a, b| b.crap.total_cmp(&a.crap));
    bad
}

#[cfg(test)]
mod tests;
