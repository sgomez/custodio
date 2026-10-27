use std::path::Path;

use super::*;

fn funcs(src: &str) -> Vec<Function> {
    functions_in(Path::new("a.rs"), src).unwrap()
}

fn c(body: &str) -> u32 {
    let f = funcs(&format!("fn f(x: i32) {{ {body} }}"));
    f[0].complexity
}

#[test]
fn straight_line_code_is_one() {
    assert_eq!(c("let _y = x + 1;"), 1);
}

#[test]
fn each_decision_adds_one() {
    assert_eq!(c("if x > 0 {}"), 2);
    assert_eq!(c("while x > 0 {}"), 2);
    assert_eq!(c("for _ in 0..x {}"), 2);
    assert_eq!(c("loop { break; }"), 2);
    assert_eq!(c("let _ = g()?;"), 2);
    assert_eq!(c("let _ = x > 0 && x < 5;"), 2);
    assert_eq!(c("let _ = x > 0 || x < 5;"), 2);
    assert_eq!(c("let _ = x + 5;"), 1);
    assert_eq!(c("let Some(_y) = g() else { return };"), 2);
}

#[test]
fn match_arms_count_beyond_the_first_and_guards_add() {
    assert_eq!(c("match x { 0 => {} 1 => {} _ => {} }"), 3);
    assert_eq!(c("match x { 0 => {} _ => {} }"), 2);
    assert_eq!(c("match x { n if n > 1 => {} _ => {} }"), 3);
}

#[test]
fn closures_count_for_the_enclosing_function_but_nested_fns_do_not() {
    assert_eq!(c("let _f = |a: i32| if a > 0 { 1 } else { 2 };"), 2);
    let all = funcs("fn outer() { fn inner(x: i32) { if x > 0 {} } }");
    let outer = all.iter().find(|f| f.name == "outer").unwrap();
    let inner = all.iter().find(|f| f.name == "inner").unwrap();
    assert_eq!(outer.complexity, 1);
    assert_eq!(inner.complexity, 2);
}

#[test]
fn test_code_is_not_scored() {
    let all = funcs(
        "fn real() {}\n#[cfg(test)]\nmod tests { fn helper() {} }\n#[test]\nfn t() {}\n\
         struct S; impl S { fn m(&self) {} #[cfg(test)] fn only_test(&self) {} }\n\
         trait T { fn d(&self) {} fn r(&self); }",
    );
    let mut names: Vec<&str> = all.iter().map(|f| f.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["d", "m", "real"]);
}

#[test]
fn lines_cover_visibility_to_brace() {
    let all = funcs("\n\npub fn f(\n    a: i32,\n) {\n}\n");
    assert_eq!((all[0].first_line, all[0].body_line), (3, 5));
    let all = funcs("fn g() {}");
    assert_eq!((all[0].first_line, all[0].body_line), (1, 1));
}

#[test]
fn crap_formula() {
    assert!((crap_score(1, 1.0) - 1.0).abs() < 1e-9);
    assert!((crap_score(10, 0.0) - 110.0).abs() < 1e-9);
    assert!((crap_score(10, 0.5) - 22.5).abs() < 1e-9);
    assert!((crap_score(30, 1.0) - 30.0).abs() < 1e-9);
}

fn export(regions: &str) -> String {
    format!(
        r#"{{"data":[{{"functions":[{{"name":"f","count":1,"filenames":["/w/a.rs"],"regions":{regions}}}]}}]}}"#
    )
}

#[test]
fn instances_read_code_regions_only() {
    let got = instances(&export(
        "[[5,1,9,2,3,0,0,0],[6,3,6,9,0,0,0,0],[7,3,7,4,1,0,0,1],[8,1,8,2,1,0,1,0],[8,1,8,2,1,1,1,0]]",
    ))
    .unwrap();
    assert_eq!(
        got,
        [Instance {
            file: "/w/a.rs".into(),
            start: (5, 1),
            covered: 1,
            total: 2
        }]
    );
}

#[test]
fn instances_reject_other_documents() {
    assert!(instances("not json").is_err());
    assert!(instances("{}").is_err());
    assert!(instances(&export("[[1,2,3]]")).is_err());
}

fn func(name: &str, first: usize, body: usize, complexity: u32) -> Function {
    Function {
        name: name.into(),
        file: "a.rs".into(),
        first_line: first,
        body_line: body,
        complexity,
    }
}

fn inst(line: usize, col: usize, covered: u32, total: u32) -> Instance {
    Instance {
        file: "/w/a.rs".into(),
        start: (line, col),
        covered,
        total,
    }
}

#[test]
fn score_matches_by_file_and_line_window() {
    let scored = score(
        vec![
            func("f", 10, 12, 4),
            func("g", 20, 20, 4),
            func("h", 30, 30, 4),
        ],
        &[
            inst(10, 1, 1, 2),
            inst(11, 5, 0, 1), // a closure inside `f`, not the function
            inst(20, 1, 4, 4),
            Instance {
                file: "/w/b.rs".into(),
                start: (30, 1),
                covered: 9,
                total: 9,
            },
        ],
    );
    assert!((scored[0].coverage - 0.5).abs() < 1e-9);
    assert!((scored[1].coverage - 1.0).abs() < 1e-9);
    assert!(
        scored[2].coverage.abs() < 1e-9,
        "other file, never instantiated"
    );
    assert!((scored[1].crap - 4.0).abs() < 1e-9);
}

#[test]
fn generic_functions_take_the_best_instantiation() {
    let scored = score(
        vec![func("f", 1, 1, 2)],
        &[inst(1, 1, 0, 4), inst(1, 1, 3, 4)],
    );
    assert!((scored[0].coverage - 0.75).abs() < 1e-9);
}

#[test]
fn only_scores_above_the_threshold_fail_worst_first() {
    let scored = score(
        vec![
            func("ok", 1, 1, 30),
            func("bad", 2, 2, 31),
            func("worse", 3, 3, 40),
        ],
        &[inst(1, 1, 1, 1), inst(2, 1, 1, 1), inst(3, 1, 1, 1)],
    );
    // Fully covered: CRAP equals complexity. 30 is at the threshold and passes.
    let bad: Vec<&str> = offenders(&scored, 30.0)
        .iter()
        .map(|s| s.function.name.as_str())
        .collect();
    assert_eq!(bad, ["worse", "bad"]);
}

#[test]
fn display_names_the_function() {
    let s = score(vec![func("f", 7, 7, 2)], &[inst(7, 1, 1, 2)]).remove(0);
    assert_eq!(s.to_string(), "a.rs:7 f complexity 2 coverage 50% CRAP 2.5");
}
