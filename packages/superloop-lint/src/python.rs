// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Torrust project contributors

//! Python test docstrings, parsed without importing or executing corpus code.
//!
//! The bounded carrier is an owned test file under `ci` or `tests`. Python's
//! isolated standard-library AST reader recognizes real docstrings, including
//! decorators, async functions and methods, while excluding assigned strings,
//! f-strings and executable examples. An unavailable interpreter or invalid
//! source is a named source-parse failure, never an empty successful census.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use serde::Deserialize;

use crate::census::{DocComment, TestFunction};
use crate::finding::Location;

const fn reader() -> &'static str {
    r"
import ast
import json
import re
import sys

source = sys.stdin.buffer.read().decode('utf-8')
tree = ast.parse(source)
starts = [0]
for ending in re.finditer(b'\r\n|\r|\n', source.encode('utf-8')):
    starts.append(ending.end())
documents = []
tests = []

def visit(node, nested_function=False):
    function = isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    container = isinstance(node, (ast.Module, ast.ClassDef)) or function
    if not container:
        for child in ast.iter_child_nodes(node):
            visit(child, nested_function)
        return
    doc = None
    if node.body and isinstance(node.body[0], ast.Expr):
        value = node.body[0].value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            lines = re.split(r'\r\n|\r|\n', value.value)
            while lines and not lines[-1].strip():
                lines.pop()
            first = value.lineno
            while lines and not lines[0].strip():
                lines.pop(0)
                first += 1
            doc = dict(lines=[line.strip() for line in lines], first_line=first,
                       last_line=value.end_lineno,
                       offset=starts[value.lineno - 1] + value.col_offset)
            documents.append(doc)
    if function and not nested_function and node.name.startswith('test_'):
        tests.append(dict(name=node.name, line=node.lineno,
                          offset=starts[node.lineno - 1] + node.col_offset,
                          doc=doc))
    for child in node.body:
        visit(child, nested_function or function)

visit(tree)
print(json.dumps(dict(documents=documents, tests=tests)))
"
}

#[derive(Debug, Deserialize)]
pub struct Document {
    pub lines: Vec<String>,
    pub first_line: usize,
    pub last_line: usize,
    pub offset: usize,
}

#[derive(Deserialize)]
struct Test {
    name: String,
    line: usize,
    offset: usize,
    doc: Option<Document>,
}

#[derive(Deserialize)]
pub struct Scan {
    pub documents: Vec<Document>,
    tests: Vec<Test>,
}

pub fn is_python(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension == "py")
}

/// The path convention is applied only after the corpus partition owns a file.
pub fn is_test_path(path: &Path) -> bool {
    is_python(path)
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("test_"))
        && ["ci", "tests"]
            .iter()
            .any(|directory| path.starts_with(directory))
}

pub fn scan(source: &str) -> Result<Scan, String> {
    let mut child = Command::new("python3")
        .args(["-I", "-c", reader()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("python-docstrings: cannot start python3: {error}"))?;
    let written = child
        .stdin
        .take()
        .ok_or("python-docstrings: missing input pipe")?
        .write_all(source.as_bytes());
    let output = child
        .wait_with_output()
        .map_err(|error| format!("python-docstrings: cannot wait for reader: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "python-docstrings: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    written.map_err(|error| format!("python-docstrings: cannot send source: {error}"))?;
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("python-docstrings: invalid reader result: {error}"))
}

pub fn tests(package: &str, path: &Path, source: &str) -> Result<Vec<TestFunction>, String> {
    Ok(scan(source)?
        .tests
        .into_iter()
        .map(|test| {
            let doc = test
                .doc
                .map(|doc| DocComment::from_lines(doc.lines, doc.first_line, doc.last_line));
            TestFunction::from_documentation(
                package,
                path,
                &test.name,
                Location::new(path, source, test.offset),
                test.line,
                doc,
            )
        })
        .collect())
}
