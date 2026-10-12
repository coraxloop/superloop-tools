#![deny(clippy::indexing_slicing)]

//! Hook grammar copied at 074c78c; caller transport and decoding are excluded.

use std::path::{Component, Path};

use serde_json::{Map, Value};

use crate::request::{Command, HygieneObservation, HygieneRequest};

/// One deterministic classification result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FastLane {
    /// A version-pinned table-owned read-only rule accepted the request.
    ReadOnlyAllow {
        /// Stable read-only rule name.
        rule: &'static str,
    },
    /// A mechanical request-shape defect must be corrected before policy review.
    AgentError {
        /// Stable hygiene rule name.
        rule: &'static str,
        /// Concise description of the malformed shape.
        defect: &'static str,
        /// Smallest shape correction.
        correction: &'static str,
    },
    /// No enabled deterministic rule decides the request.
    ToModel,
}

/// One disabled-until-proven harness read-only claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadOnlyEntry {
    /// Stable claim name.
    pub entry: &'static str,
    /// Complete candidate grammar represented by the matcher.
    pub grammar: &'static str,
    /// Whether the acceptance matrix has enabled this claim.
    pub accepted: bool,
}

/// Version-pinned read-only claim table. Bite one deliberately enables no row.
pub const READ_ONLY_TABLE: &[ReadOnlyEntry] = &[
    ReadOnlyEntry {
        entry: "native-read",
        grammar: "Read object: project-relative nonsensitive file_path; optional offset and limit are nonnegative integers",
        accepted: false,
    },
    ReadOnlyEntry {
        entry: "native-glob",
        grammar: "Glob object: nonempty pattern and optional project-relative path; neither escapes the project",
        accepted: false,
    },
    ReadOnlyEntry {
        entry: "native-grep",
        grammar: "Grep object: nonempty pattern and optional project-relative path; target is neither outside nor sensitive",
        accepted: false,
    },
    ReadOnlyEntry {
        entry: "native-web-search",
        grammar: "WebSearch object: nonempty query with no credential-shaped value",
        accepted: false,
    },
    ReadOnlyEntry {
        entry: "native-get-web-fetch",
        grammar: "WebFetch object: HTTP(S) url, absent or GET method, no body or upload field, and no credential-shaped URL",
        accepted: false,
    },
    ReadOnlyEntry {
        entry: "bash-filesystem-observation",
        grammar: "one simple redirect-free and substitution-free pwd, ls, stat, file, readlink, or wc command with only encoded observation options and project-relative operands",
        accepted: false,
    },
    ReadOnlyEntry {
        entry: "bash-source-observation",
        grammar: "one simple redirect-free and substitution-free rg, grep, sed -n, head, tail, or read-only jq command with encoded options and project-relative file operands",
        accepted: false,
    },
    ReadOnlyEntry {
        entry: "bash-repository-observation",
        grammar: "one simple redirect-free and substitution-free git status, diff, log, show, or rev-parse command without relocation, remote contact, or mutation",
        accepted: false,
    },
];

#[derive(Clone, Copy)]
struct ShellInput<'a> {
    command: &'a str,
    timeout_ms: Option<u64>,
    declared_background: Option<bool>,
}

fn shell_input<'a>(
    request: &'a impl HygieneRequest,
    observation: &HygieneObservation<'_>,
) -> Option<ShellInput<'a>> {
    let HygieneObservation::Shell {
        timeout_ms,
        declared_background,
    } = observation
    else {
        return None;
    };
    let Command::Bytes { bytes } = request.command() else {
        return None;
    };
    Some(ShellInput {
        command: std::str::from_utf8(bytes).ok()?,
        timeout_ms: *timeout_ms,
        declared_background: *declared_background,
    })
}

/// One ordered mechanical hygiene rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HygieneRule {
    /// Stable rule name.
    pub rule: &'static str,
    /// Concise defect returned to the caller.
    pub defect: &'static str,
    /// Smallest correction returned to the caller.
    pub correction: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HygieneRuleId {
    RemoteTimeout,
    BackgroundContract,
    ExecutionTiming,
    OneObjective,
    PipelineStatus,
    DestructiveOperands,
    RemotePrivilege,
    ParseableSyntax,
}

impl HygieneRuleId {
    /// First identifier in crate table order.
    pub const FIRST: Self = Self::RemoteTimeout;

    /// Identifier that follows this one in crate table order, or `None` at the end.
    ///
    /// The match carries no wildcard, so a new variant must be given an arm here. A variant wired
    /// into this order raises [`HYGIENE_RULE_COUNT`], and the crate table then fails to compile
    /// until its rule is added. A variant whose arm ends the chain instead, one that no other arm
    /// points to, is still not forced into the table: closing that needs a generated enum or a
    /// compiler-provided variant count, neither of which this crate has.
    #[must_use]
    pub const fn successor(self) -> Option<Self> {
        match self {
            Self::RemoteTimeout => Some(Self::BackgroundContract),
            Self::BackgroundContract => Some(Self::ExecutionTiming),
            Self::ExecutionTiming => Some(Self::OneObjective),
            Self::OneObjective => Some(Self::PipelineStatus),
            Self::PipelineStatus => Some(Self::DestructiveOperands),
            Self::DestructiveOperands => Some(Self::RemotePrivilege),
            Self::RemotePrivilege => Some(Self::ParseableSyntax),
            Self::ParseableSyntax => None,
        }
    }
}

/// Number of mechanical hygiene rules, counted along [`HygieneRuleId::successor`] from
/// [`HygieneRuleId::FIRST`].
///
/// Only that wildcard-free match can produce this value, so the crate table's declared length
/// follows the enum rather than a hand-maintained literal for every variant wired into the order.
pub const HYGIENE_RULE_COUNT: usize = {
    let mut count = 1;
    let mut current = HygieneRuleId::FIRST;
    while let Some(next) = current.successor() {
        count += 1;
        current = next;
    }
    count
};

#[must_use]
pub const fn hygiene_rule(id: HygieneRuleId) -> &'static HygieneRule {
    match id {
        HygieneRuleId::RemoteTimeout => &HygieneRule {
            rule: "remote-whole-request-timeout",
            defect: "remote execution or transfer has no finite positive whole-request timeout",
            correction: "set a finite positive Bash timeout or wrap the complete request with leading timeout N",
        },
        HygieneRuleId::BackgroundContract => &HygieneRule {
            rule: "background-observation-contract",
            defect: "background execution lacks a complete bounded observation contract",
            correction: "declare background execution with a finite startup timeout, stable job identity, append-only log, completion marker, and supervised status command",
        },
        HygieneRuleId::ExecutionTiming => &HygieneRule {
            rule: "execution-boundary-timing",
            defect: "a build, test, linter, installation, image build, or long gate is not timed at its execution boundary",
            correction: "wrap the gate process itself with time so elapsed wall time and child status are emitted",
        },
        HygieneRuleId::OneObjective => &HygieneRule {
            rule: "one-mutating-objective",
            defect: "one mutating batch contains multiple operational objectives or failure domains",
            correction: "split independent mutations, publication, configuration, and verification into separate requests",
        },
        HygieneRuleId::PipelineStatus => &HygieneRule {
            rule: "pipeline-producer-status",
            defect: "a pipeline after a mutation or gate can hide the producer's failure status",
            correction: "enable pipeline failure propagation and preserve the producer status explicitly",
        },
        HygieneRuleId::DestructiveOperands => &HygieneRule {
            rule: "bounded-destructive-operands",
            defect: "a destructive operand is unresolved, implicit, traversing, wildcarded, substituted, empty, or broadly rooted",
            correction: "name and validate one explicit bounded target before submitting the destructive command",
        },
        HygieneRuleId::RemotePrivilege => &HygieneRule {
            rule: "remote-privilege-noninteractive-alias",
            defect: "a remote privileged command can prompt or addresses an endpoint instead of a configured alias",
            correction: "use a configured alias with non-interactive SSH host authentication and non-interactive privilege flags",
        },
        HygieneRuleId::ParseableSyntax => &HygieneRule {
            rule: "parseable-executable-syntax",
            defect: "the command is plainly malformed shell or contains an unevaluated prose placeholder",
            correction: "submit complete executable shell where every trailing connector has a consumer and quotes, substitutions, subshells, and heredocs are closed",
        },
    }
}

/// Ordered mechanical hygiene rules applied before read-only claims.
pub const HYGIENE_RULES: &[HygieneRule; HYGIENE_RULE_COUNT] = &[
    *hygiene_rule(HygieneRuleId::RemoteTimeout),
    *hygiene_rule(HygieneRuleId::BackgroundContract),
    *hygiene_rule(HygieneRuleId::ExecutionTiming),
    *hygiene_rule(HygieneRuleId::OneObjective),
    *hygiene_rule(HygieneRuleId::PipelineStatus),
    *hygiene_rule(HygieneRuleId::DestructiveOperands),
    *hygiene_rule(HygieneRuleId::RemotePrivilege),
    *hygiene_rule(HygieneRuleId::ParseableSyntax),
];

/// Apply ordered mechanical checks and then the disabled-until-proven read table.
#[must_use]
pub(super) fn classify(
    request: &impl HygieneRequest,
    observation: &HygieneObservation<'_>,
) -> FastLane {
    if let Some(shell) = shell_input(request, observation) {
        match tokenize(shell.command) {
            ShellParse::PlainlyInvalid => return agent_error(HygieneRuleId::ParseableSyntax),
            ShellParse::Ambiguous(shape) => {
                let nested = nested_shell_shapes(&shape);
                if let Some(defect) =
                    ambiguous_hygiene_defect(&shell, &shape, &nested, request.cwd())
                {
                    return agent_error(defect);
                }
                return FastLane::ToModel;
            }
            ShellParse::Parsed(shape) => {
                if remote_timeout_defect(&shell, &shape) {
                    return agent_error(HygieneRuleId::RemoteTimeout);
                }
                if background_contract_defect(&shell, &shape) {
                    return agent_error(HygieneRuleId::BackgroundContract);
                }
                let nested = nested_shell_shapes(&shape);
                if nested.ambiguous {
                    if let Some(defect) =
                        ambiguous_hygiene_defect(&shell, &shape, &nested, request.cwd())
                    {
                        return agent_error(defect);
                    }
                    return FastLane::ToModel;
                }
                if nested.plainly_invalid {
                    return agent_error(HygieneRuleId::ParseableSyntax);
                }
                if timing_defect(&shape) {
                    return agent_error(HygieneRuleId::ExecutionTiming);
                }
                if mutating_batch_defect(&shape) {
                    return agent_error(HygieneRuleId::OneObjective);
                }
                if pipeline_status_defect(&shape, &nested.parsed) {
                    return agent_error(HygieneRuleId::PipelineStatus);
                }
                if destructive_operand_defect(&shape, &nested.parsed, request.cwd()) {
                    return agent_error(HygieneRuleId::DestructiveOperands);
                }
                if remote_privilege_defect(&shape) {
                    return agent_error(HygieneRuleId::RemotePrivilege);
                }
            }
        }
    }

    matching_read_only_entry(request, observation).map_or(FastLane::ToModel, |entry| {
        if entry.accepted {
            FastLane::ReadOnlyAllow { rule: entry.entry }
        } else {
            FastLane::ToModel
        }
    })
}

/// Return the disabled or enabled read-only table row whose exact grammar matches.
#[must_use]
pub fn matching_read_only_entry(
    request: &impl HygieneRequest,
    observation: &HygieneObservation<'_>,
) -> Option<&'static ReadOnlyEntry> {
    let name = match observation {
        HygieneObservation::Native { tool, fields } => match *tool {
            "Read" if native_read_matches(fields) => "native-read",
            "Glob" if native_glob_matches(fields) => "native-glob",
            "Grep" if native_grep_matches(fields) => "native-grep",
            "WebSearch" if native_web_search_matches(fields) => "native-web-search",
            "WebFetch" if native_web_fetch_matches(fields) => "native-get-web-fetch",
            _ => return None,
        },
        HygieneObservation::Shell { .. } => shell_read_entry(&shell_input(request, observation)?)?,
    };
    READ_ONLY_TABLE.iter().find(|entry| entry.entry == name)
}

const fn agent_error(id: HygieneRuleId) -> FastLane {
    let rule = hygiene_rule(id);
    FastLane::AgentError {
        rule: rule.rule,
        defect: rule.defect,
        correction: rule.correction,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Word {
    text: String,
    substitution: bool,
    unquoted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Connector {
    Pipe,
    And,
    Or,
    Sequence,
    Background,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RedirectKind {
    Read,
    Write,
    Append,
    Descriptor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Redirect {
    kind: RedirectKind,
    target: Word,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SimpleCommand {
    words: Vec<Word>,
    redirects: Vec<Redirect>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ShellShape {
    commands: Vec<SimpleCommand>,
    connectors: Vec<Connector>,
    has_subshell: bool,
    /// Command-substitution bodies lifted out of an opaque arithmetic command or expansion.
    arithmetic_substitutions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Word(Word),
    Connector(Connector),
    Redirect(RedirectKind),
    LeftParen,
    RightParen,
}

enum ShellParse {
    Parsed(ShellShape),
    PlainlyInvalid,
    Ambiguous(ShellShape),
}

fn tokenize(input: &str) -> ShellParse {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return ShellParse::PlainlyInvalid;
    }
    let normalized = trimmed
        .strip_suffix(';')
        .map(str::trim_end)
        .filter(|command| !command.ends_with(';'))
        .unwrap_or(trimmed);
    let mut parse = tokenize_normalized(normalized);
    if let ShellParse::Parsed(shape) | ShellParse::Ambiguous(shape) = &mut parse {
        shape
            .arithmetic_substitutions
            .extend(arithmetic_expansion_substitutions(normalized));
    }
    parse
}

fn tokenize_normalized(normalized: &str) -> ShellParse {
    match heredoc_shape(normalized) {
        HeredocShape::Malformed => return ShellParse::PlainlyInvalid,
        HeredocShape::Present(offset) => return ambiguous_prefix(normalized, offset),
        HeredocShape::Absent => {}
    }
    if let Some(offset) = unquoted_process_substitution(normalized) {
        return ambiguous_prefix(normalized, offset);
    }
    if let Some(offset) = unquoted_arithmetic_command(normalized) {
        return ambiguous_arithmetic(normalized, offset);
    }

    let cs: Vec<_> = normalized.chars().collect();
    let tokens = match scan_tokens(&cs) {
        Ok(tokens) => tokens,
        Err(parse) => return parse,
    };
    if tokens_have_plain_placeholder(&tokens) {
        return ShellParse::PlainlyInvalid;
    }
    if tokens_have_unevaluated_parenthetical(&tokens) {
        return ShellParse::PlainlyInvalid;
    }

    build_shape(tokens)
}

struct Tokenizer<'a> {
    cs: &'a [char],
    tokens: Vec<Token>,
    word: String,
    word_started: bool,
    substitution: bool,
    unquoted: bool,
    index: usize,
}

impl Tokenizer<'_> {
    fn scan_one(&mut self) -> Result<(), ShellParse> {
        let Some(current) = self.cs.get(self.index).copied() else {
            return Ok(());
        };
        match current {
            ' ' | '\t' | '\r' => {
                self.push_word();
                self.index += 1;
            }
            '\n' => {
                self.push_word();
                push_sequence(&mut self.tokens);
                self.index += 1;
            }
            '#' if !self.word_started => {
                self.push_word();
                while self
                    .cs
                    .get(self.index)
                    .is_some_and(|current| *current != '\n')
                {
                    self.index += 1;
                }
            }
            '\'' => {
                self.consume_single_quote()?;
            }
            '"' => {
                self.word_started = true;
                self.index += 1;
                if consume_double_quote(
                    self.cs,
                    &mut self.index,
                    &mut self.word,
                    &mut self.substitution,
                )
                .is_err()
                {
                    return Err(ShellParse::PlainlyInvalid);
                }
            }
            '\\' => {
                self.word_started = true;
                self.unquoted = true;
                self.index += 1;
                let Some(escaped) = self.cs.get(self.index).copied() else {
                    return Err(ShellParse::PlainlyInvalid);
                };
                if escaped != '\n' {
                    self.word.push(escaped);
                }
                self.index += 1;
            }
            '$' if self.cs.get(self.index + 1) == Some(&'(') => {
                self.mark_substitution();
                if consume_substitution(self.cs, &mut self.index, &mut self.word).is_err() {
                    return Err(ShellParse::PlainlyInvalid);
                }
            }
            '$' if self.cs.get(self.index + 1) == Some(&'{') => {
                self.mark_substitution();
                if consume_braced_variable(self.cs, &mut self.index, &mut self.word).is_err() {
                    return Err(ShellParse::PlainlyInvalid);
                }
            }
            '$' if self
                .cs
                .get(self.index + 1)
                .is_some_and(|next| variable_start(*next)) =>
            {
                self.mark_substitution();
                consume_dollar_variable(self.cs, &mut self.index, &mut self.word);
            }
            '`' => {
                self.mark_substitution();
                if consume_backticks(self.cs, &mut self.index, &mut self.word).is_err() {
                    return Err(ShellParse::PlainlyInvalid);
                }
            }
            '<' if self.consume_angle_placeholder() => {}
            operator @ ('|' | '&' | ';' | '(' | ')' | '<' | '>') => {
                self.scan_operator_token(operator)?;
            }
            _ => {
                self.word_started = true;
                self.unquoted = true;
                self.word.push(current);
                self.index += 1;
            }
        }
        Ok(())
    }

    const fn mark_substitution(&mut self) {
        self.word_started = true;
        self.substitution = true;
        self.unquoted = true;
    }

    fn consume_single_quote(&mut self) -> Result<(), ShellParse> {
        self.word_started = true;
        self.index += 1;
        while let Some(current) = self.cs.get(self.index).copied() {
            if current == '\'' {
                self.index += 1;
                return Ok(());
            }
            self.word.push(current);
            self.index += 1;
        }
        Err(ShellParse::PlainlyInvalid)
    }

    fn push_word(&mut self) {
        push_word(
            &mut self.tokens,
            &mut self.word,
            &mut self.word_started,
            &mut self.substitution,
            &mut self.unquoted,
        );
    }

    fn scan_operator_token(&mut self, operator: char) -> Result<(), ShellParse> {
        if matches!(operator, '<' | '>') && self.pending_descriptor() {
            self.clear_word();
        } else {
            self.push_word();
        }
        let Some(token) = scan_operator(self.cs, &mut self.index) else {
            return Err(ShellParse::Ambiguous(ShellShape::default()));
        };
        self.tokens.push(token);
        Ok(())
    }

    fn pending_descriptor(&self) -> bool {
        self.word_started
            && self.unquoted
            && !self.substitution
            && !self.word.is_empty()
            && self.word.chars().all(|current| current.is_ascii_digit())
    }

    fn clear_word(&mut self) {
        self.word.clear();
        self.word_started = false;
        self.substitution = false;
        self.unquoted = false;
    }

    fn consume_angle_placeholder(&mut self) -> bool {
        let Some(following) = self.cs.get(self.index + 1).copied() else {
            return false;
        };
        if !following.is_ascii_alphanumeric() && following != '_' {
            return false;
        }
        let search_start = self.index.saturating_add(2);
        let Some(tail) = self.cs.get(search_start..) else {
            return false;
        };
        let Some(relative_end) = tail.iter().position(|current| *current == '>') else {
            return false;
        };
        let end = search_start + relative_end;
        let Some(content) = self.cs.get(self.index + 1..end) else {
            return false;
        };
        let content: String = content.iter().copied().collect();
        if !matches!(content.to_ascii_lowercase().as_str(), "command" | "path") {
            return false;
        }
        self.word_started = true;
        self.unquoted = true;
        let Some(placeholder) = self.cs.get(self.index..=end) else {
            return false;
        };
        self.word.extend(placeholder.iter().copied());
        self.index = end + 1;
        true
    }
}

fn scan_tokens(cs: &[char]) -> Result<Vec<Token>, ShellParse> {
    let mut tokenizer = Tokenizer {
        cs,
        tokens: Vec::new(),
        word: String::new(),
        word_started: false,
        substitution: false,
        unquoted: false,
        index: 0,
    };
    while tokenizer.index < cs.len() {
        tokenizer.scan_one()?;
    }
    tokenizer.push_word();
    Ok(tokenizer.tokens)
}

fn push_word(
    tokens: &mut Vec<Token>,
    word: &mut String,
    started: &mut bool,
    substitution: &mut bool,
    unquoted: &mut bool,
) {
    if *started {
        tokens.push(Token::Word(Word {
            text: std::mem::take(word),
            substitution: *substitution,
            unquoted: *unquoted,
        }));
        *started = false;
        *substitution = false;
        *unquoted = false;
    }
}

fn push_sequence(tokens: &mut Vec<Token>) {
    if !tokens.is_empty() && !matches!(tokens.last(), Some(Token::Connector(_) | Token::LeftParen))
    {
        tokens.push(Token::Connector(Connector::Sequence));
    }
}

fn consume_double_quote(
    cs: &[char],
    index: &mut usize,
    word: &mut String,
    substitution: &mut bool,
) -> Result<(), ()> {
    while let Some(current) = cs.get(*index).copied() {
        match current {
            '"' => {
                *index += 1;
                return Ok(());
            }
            '\\' => {
                *index += 1;
                let Some(escaped) = cs.get(*index).copied() else {
                    return Err(());
                };
                word.push(escaped);
                *index += 1;
            }
            '$' if cs.get(*index + 1) == Some(&'(') => {
                *substitution = true;
                consume_substitution(cs, index, word)?;
            }
            '$' if cs.get(*index + 1) == Some(&'{') => {
                *substitution = true;
                consume_braced_variable(cs, index, word)?;
            }
            '$' if cs.get(*index + 1).is_some_and(|next| variable_start(*next)) => {
                *substitution = true;
                consume_dollar_variable(cs, index, word);
            }
            '`' => {
                *substitution = true;
                consume_backticks(cs, index, word)?;
            }
            current => {
                word.push(current);
                *index += 1;
            }
        }
    }
    Err(())
}

fn consume_substitution(cs: &[char], index: &mut usize, word: &mut String) -> Result<(), ()> {
    let mut depth = 0_u32;
    let mut quote = None;
    while let Some(current) = cs.get(*index).copied() {
        word.push(current);
        *index += 1;
        if current == '\\' {
            if let Some(escaped) = cs.get(*index).copied() {
                word.push(escaped);
                *index += 1;
            }
            continue;
        }
        if let Some(active) = quote {
            if current == active {
                quote = None;
            }
            continue;
        }
        if current == '\'' || current == '"' {
            quote = Some(current);
        } else if current == '(' {
            depth = depth.saturating_add(1);
        } else if current == ')' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Ok(());
            }
        }
    }
    Err(())
}

fn consume_braced_variable(cs: &[char], index: &mut usize, word: &mut String) -> Result<(), ()> {
    let mut depth = 0_u32;
    while let Some(current) = cs.get(*index).copied() {
        word.push(current);
        *index += 1;
        if current == '\\' {
            if let Some(escaped) = cs.get(*index).copied() {
                word.push(escaped);
                *index += 1;
            }
        } else if current == '{' {
            depth = depth.saturating_add(1);
        } else if current == '}' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Ok(());
            }
        }
    }
    Err(())
}

fn consume_dollar_variable(cs: &[char], index: &mut usize, word: &mut String) {
    word.push('$');
    *index += 1;
    if let Some(current) = cs.get(*index).copied() {
        word.push(current);
        *index += 1;
        if current == '_' || current.is_ascii_alphabetic() {
            while let Some(following) = cs.get(*index).copied() {
                if following != '_' && !following.is_ascii_alphanumeric() {
                    break;
                }
                word.push(following);
                *index += 1;
            }
        }
    }
}

const fn variable_start(current: char) -> bool {
    current == '_'
        || current.is_ascii_alphanumeric()
        || matches!(current, '?' | '#' | '!' | '$' | '*' | '@' | '-')
}

fn consume_backticks(cs: &[char], index: &mut usize, word: &mut String) -> Result<(), ()> {
    word.push('`');
    *index += 1;
    while let Some(current) = cs.get(*index).copied() {
        word.push(current);
        *index += 1;
        if current == '\\' {
            if let Some(escaped) = cs.get(*index).copied() {
                word.push(escaped);
                *index += 1;
            }
        } else if current == '`' {
            return Ok(());
        }
    }
    Err(())
}

fn scan_operator(cs: &[char], index: &mut usize) -> Option<Token> {
    let current = cs.get(*index).copied()?;
    *index += 1;
    match current {
        '|' if cs.get(*index) == Some(&'|') => {
            *index += 1;
            Some(Token::Connector(Connector::Or))
        }
        '|' if cs.get(*index) == Some(&'&') => {
            *index += 1;
            Some(Token::Connector(Connector::Pipe))
        }
        '|' => Some(Token::Connector(Connector::Pipe)),
        '&' if cs.get(*index) == Some(&'&') => {
            *index += 1;
            Some(Token::Connector(Connector::And))
        }
        '&' => Some(Token::Connector(Connector::Background)),
        ';' if cs.get(*index) == Some(&';') => {
            *index += 1;
            Some(Token::Connector(Connector::Sequence))
        }
        ';' => Some(Token::Connector(Connector::Sequence)),
        '(' => Some(Token::LeftParen),
        ')' => Some(Token::RightParen),
        '<' if cs.get(*index) == Some(&'<') => None,
        '<' if cs.get(*index) == Some(&'&') => {
            *index += 1;
            Some(Token::Redirect(RedirectKind::Descriptor))
        }
        '<' => Some(Token::Redirect(RedirectKind::Read)),
        '>' if cs.get(*index) == Some(&'>') => {
            *index += 1;
            Some(Token::Redirect(RedirectKind::Append))
        }
        '>' if cs.get(*index) == Some(&'&') => {
            *index += 1;
            Some(Token::Redirect(RedirectKind::Descriptor))
        }
        '>' => {
            if cs.get(*index) == Some(&'|') {
                *index += 1;
            }
            Some(Token::Redirect(RedirectKind::Write))
        }
        _ => None,
    }
}

fn build_shape(tokens: Vec<Token>) -> ShellParse {
    let mut commands: Vec<SimpleCommand> = Vec::new();
    let mut connectors = Vec::new();
    let mut command = SimpleCommand::default();
    let mut pending_redirect = None;
    let mut paren_depth = 0_u32;
    let mut has_subshell = false;
    let mut just_closed = false;
    let mut redirecting_closed = false;
    let mut ambiguous_structure = false;

    for token in tokens {
        match token {
            Token::Word(word) => {
                if let Some(kind) = pending_redirect.take() {
                    if attach_redirect(&mut commands, &mut command, kind, word, redirecting_closed)
                        .is_err()
                    {
                        return ShellParse::PlainlyInvalid;
                    }
                } else {
                    if just_closed || redirecting_closed {
                        ambiguous_structure = true;
                        just_closed = false;
                        redirecting_closed = false;
                    }
                    command.words.push(word);
                }
            }
            Token::Redirect(kind) => {
                if pending_redirect.replace(kind).is_some() {
                    return ShellParse::PlainlyInvalid;
                }
                redirecting_closed |= just_closed;
                just_closed = false;
            }
            Token::Connector(connector) => {
                if pending_redirect.is_some() {
                    return ShellParse::PlainlyInvalid;
                }
                if command.words.is_empty() {
                    if !just_closed && !redirecting_closed {
                        return ShellParse::PlainlyInvalid;
                    }
                } else {
                    commands.push(std::mem::take(&mut command));
                }
                connectors.push(connector);
                just_closed = false;
                redirecting_closed = false;
            }
            Token::LeftParen => {
                if pending_redirect.is_some() || just_closed {
                    return ShellParse::PlainlyInvalid;
                }
                if !command.words.is_empty() {
                    commands.push(std::mem::take(&mut command));
                    ambiguous_structure = true;
                }
                paren_depth = paren_depth.saturating_add(1);
                has_subshell = true;
            }
            Token::RightParen => {
                if pending_redirect.is_some() {
                    return ShellParse::PlainlyInvalid;
                }
                if paren_depth == 0 {
                    if command.words.first().is_none_or(|word| word.text != "case")
                        && !commands.iter().any(|candidate| {
                            candidate
                                .words
                                .first()
                                .is_some_and(|word| word.text == "case")
                        })
                    {
                        return ShellParse::PlainlyInvalid;
                    }
                    if !command.words.is_empty() {
                        commands.push(std::mem::take(&mut command));
                    }
                    ambiguous_structure = true;
                    just_closed = true;
                    continue;
                }
                if !command.words.is_empty() {
                    commands.push(std::mem::take(&mut command));
                }
                paren_depth -= 1;
                just_closed = true;
                redirecting_closed = false;
            }
        }
    }
    finish_shape(
        commands,
        connectors,
        command,
        pending_redirect,
        paren_depth,
        has_subshell,
        ambiguous_structure,
    )
}

fn attach_redirect(
    commands: &mut [SimpleCommand],
    command: &mut SimpleCommand,
    kind: RedirectKind,
    target: Word,
    to_closed: bool,
) -> Result<(), ()> {
    if to_closed {
        let closed = commands.last_mut().ok_or(())?;
        closed.redirects.push(Redirect { kind, target });
    } else {
        command.redirects.push(Redirect { kind, target });
    }
    Ok(())
}

fn finish_shape(
    mut commands: Vec<SimpleCommand>,
    connectors: Vec<Connector>,
    command: SimpleCommand,
    pending_redirect: Option<RedirectKind>,
    paren_depth: u32,
    has_subshell: bool,
    ambiguous_structure: bool,
) -> ShellParse {
    if pending_redirect.is_some() || paren_depth != 0 {
        return ShellParse::PlainlyInvalid;
    }
    if !command.words.is_empty() {
        commands.push(command);
    }
    if commands.is_empty() {
        return ShellParse::PlainlyInvalid;
    }
    if connectors.len() >= commands.len() && connectors.last() != Some(&Connector::Background) {
        return ShellParse::PlainlyInvalid;
    }

    let shape = ShellShape {
        commands,
        connectors,
        has_subshell,
        arithmetic_substitutions: Vec::new(),
    };
    if ambiguous_structure || shape.commands.iter().any(unmodelled_command_head) {
        ShellParse::Ambiguous(shape)
    } else {
        ShellParse::Parsed(shape)
    }
}

fn shell_keyword_head(command: &SimpleCommand) -> bool {
    command.words.first().is_some_and(|word| {
        matches!(
            word.text.as_str(),
            "for"
                | "while"
                | "if"
                | "then"
                | "do"
                | "else"
                | "{"
                | "}"
                | "case"
                | "until"
                | "function"
                | "done"
                | "fi"
                | "esac"
                | "in"
                | "select"
        )
    })
}

fn unmodelled_command_head(command: &SimpleCommand) -> bool {
    shell_keyword_head(command)
        || command.words.first().is_some_and(|word| {
            matches!(
                word.text.as_str(),
                "!" | "eval" | "exec" | "source" | "." | "[[" | "coproc"
            )
        })
}

fn tokens_have_plain_placeholder(tokens: &[Token]) -> bool {
    tokens.iter().any(|token| {
        matches!(
            token,
            Token::Word(Word {
                text,
                unquoted: true,
                ..
            }) if matches!(text.to_ascii_lowercase().as_str(), "replace_me" | "..." | "<command>" | "<path>")
        )
    })
}

fn tokens_have_unevaluated_parenthetical(tokens: &[Token]) -> bool {
    tokens.iter().enumerate().any(|(index, token)| {
        let Token::Word(word) = token else {
            return false;
        };
        if tokens.get(index.saturating_add(1)) != Some(&Token::LeftParen) {
            return false;
        }
        let array_assignment = word.text.ends_with('=') && assignment_word(&word.text);
        let function_definition = shell_function_name(&word.text)
            && tokens.get(index.saturating_add(2)) == Some(&Token::RightParen);
        !array_assignment && !function_definition
    })
}

fn shell_function_name(word: &str) -> bool {
    let mut characters = word.chars();
    characters
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && characters.all(|current| current == '_' || current.is_ascii_alphanumeric())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeredocShape {
    Absent,
    Present(usize),
    Malformed,
}

fn heredoc_shape(command: &str) -> HeredocShape {
    let Some(marker) = unquoted_heredoc_marker(command) else {
        return HeredocShape::Absent;
    };
    if command.as_bytes().get(marker.saturating_add(2)) == Some(&b'<') {
        return HeredocShape::Absent;
    }
    let Some(after) = command.get(marker.saturating_add(2)..) else {
        return HeredocShape::Malformed;
    };
    let Some(line_end) = after.find('\n') else {
        return HeredocShape::Malformed;
    };
    let Some(declaration) = after.get(..line_end).map(str::trim_start) else {
        return HeredocShape::Malformed;
    };
    let delimiter = declaration
        .strip_prefix('-')
        .unwrap_or(declaration)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(['\'', '"']);
    if delimiter.is_empty() {
        return HeredocShape::Malformed;
    }
    if after
        .get(line_end.saturating_add(1)..)
        .is_some_and(|body| body.lines().any(|line| line.trim_end() == delimiter))
    {
        HeredocShape::Present(marker)
    } else {
        HeredocShape::Malformed
    }
}

/// Offset of the `$` opening the first unquoted `$((` arithmetic expansion.
fn unquoted_arithmetic_expansion(command: &str) -> Option<usize> {
    let mut quote = None;
    let mut escaped = false;
    for (offset, current) in command.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some('\'') {
            if current == '\'' {
                quote = None;
            }
            continue;
        }
        if current == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if current == active {
                quote = None;
            }
            continue;
        }
        if current == '\'' || current == '"' {
            quote = Some(current);
        } else if current == '$'
            && command
                .get(offset.saturating_add(1)..)
                .is_some_and(|rest| rest.starts_with("(("))
        {
            return Some(offset);
        }
    }
    None
}

/// Substitution bodies lifted out of every unquoted `$((…))` expansion in one command.
///
/// An arithmetic expansion is opaque to the tokenizer exactly as an arithmetic command is, so a
/// `$(…)` written inside one would otherwise be invisible to the hygiene set. Only the arithmetic
/// is entered: an ordinary `$(…)` elsewhere in the command is left alone.
fn arithmetic_expansion_substitutions(command: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut remainder = command;
    while let Some(offset) = unquoted_arithmetic_expansion(remainder) {
        let Some(body_start) = remainder.get(offset.saturating_add(3)..) else {
            break;
        };
        let Some(end) = arithmetic_command_end(body_start) else {
            break;
        };
        let Some(body) = body_start.get(..end) else {
            break;
        };
        collect_arithmetic_substitutions(body, &mut commands);
        let Some(rest) = body_start.get(end.saturating_add(2)..) else {
            break;
        };
        remainder = rest;
    }
    commands
}

fn unquoted_process_substitution(command: &str) -> Option<usize> {
    let mut characters = command.char_indices().peekable();
    let mut quote = None;
    let mut escaped = false;
    while let Some((offset, current)) = characters.next() {
        if escaped {
            escaped = false;
            continue;
        }
        if current == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if current == active {
                quote = None;
            }
            continue;
        }
        if current == '\'' || current == '"' {
            quote = Some(current);
        } else if matches!(current, '<' | '>')
            && characters
                .peek()
                .is_some_and(|(_, following)| *following == '(')
        {
            return Some(offset);
        }
    }
    None
}

fn unquoted_arithmetic_command(command: &str) -> Option<usize> {
    let mut characters = command.char_indices().peekable();
    let mut quote = None;
    let mut escaped = false;
    let mut previous = None;
    while let Some((offset, current)) = characters.next() {
        if escaped {
            escaped = false;
            previous = Some(current);
            continue;
        }
        if current == '\\' {
            escaped = true;
            previous = Some(current);
            continue;
        }
        if let Some(active) = quote {
            if current == active {
                quote = None;
            }
            previous = Some(current);
            continue;
        }
        if current == '\'' || current == '"' {
            quote = Some(current);
        } else if current == '('
            && previous != Some('$')
            && characters
                .peek()
                .is_some_and(|(_, following)| *following == '(')
        {
            return Some(offset);
        }
        previous = Some(current);
    }
    None
}

fn ambiguous_arithmetic(command: &str, first_offset: usize) -> ShellParse {
    let mut substitutions = Vec::new();
    let Some(masked) = mask_arithmetic_commands(command, &mut substitutions) else {
        return ambiguous_prefix(command, first_offset);
    };
    let cs: Vec<_> = masked.chars().collect();
    let mut shape = match scan_tokens(&cs) {
        Ok(tokens) => match build_shape(tokens) {
            ShellParse::Parsed(shape) | ShellParse::Ambiguous(shape) => shape,
            ShellParse::PlainlyInvalid => return ShellParse::PlainlyInvalid,
        },
        Err(ShellParse::Parsed(shape) | ShellParse::Ambiguous(shape)) => shape,
        Err(ShellParse::PlainlyInvalid) => return ShellParse::PlainlyInvalid,
    };
    shape.arithmetic_substitutions = substitutions;
    ShellParse::Ambiguous(shape)
}

fn mask_arithmetic_commands(command: &str, substitutions: &mut Vec<String>) -> Option<String> {
    let mut masked = String::with_capacity(command.len());
    let mut remainder = command;
    while let Some(offset) = unquoted_arithmetic_command(remainder) {
        masked.push_str(remainder.get(..offset)?);
        masked.push_str("__permission_triage_arithmetic__");
        let body = remainder.get(offset.saturating_add(2)..)?;
        let end = arithmetic_command_end(body)?;
        collect_arithmetic_substitutions(body.get(..end)?, substitutions);
        remainder = body.get(end.saturating_add(2)..)?;
    }
    masked.push_str(remainder);
    Some(masked)
}

/// How the text being scanned quotes: an arithmetic expression is not ordinary shell.
///
/// An arithmetic expression is evaluated as if it were inside double quotes, so a single quote in
/// it is an ordinary character and a `$(…)` written between two of them is still substituted. The
/// body of that substitution, by contrast, is ordinary shell and quotes normally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuotingLevel {
    Arithmetic,
    Shell,
}

/// Collect the body of every command substitution nested anywhere inside one arithmetic expression.
///
/// The arithmetic itself stays opaque, but a substitution inside it is ordinary shell that the
/// hygiene set must still see. Nesting is followed to any depth through a work list rather than
/// recursion; the scanned-byte budget only bounds pathological input and leaves the arithmetic
/// masked exactly as before, so exhausting it can never turn a denial into an allow.
fn collect_arithmetic_substitutions(body: &str, commands: &mut Vec<String>) {
    const MAX_SCANNED_BYTES: usize = 1 << 20;
    let mut pending = vec![(body.to_owned(), QuotingLevel::Arithmetic)];
    let mut scanned = 0_usize;
    while let Some((current, level)) = pending.pop() {
        scanned = scanned.saturating_add(current.len());
        if scanned > MAX_SCANNED_BYTES {
            return;
        }
        scan_substitution_bodies(&current, level, commands, &mut pending);
    }
}

fn scan_substitution_bodies(
    source: &str,
    level: QuotingLevel,
    commands: &mut Vec<String>,
    pending: &mut Vec<(String, QuotingLevel)>,
) {
    let single_quotes = level == QuotingLevel::Shell;
    let mut index = 0_usize;
    let mut quote = None;
    let mut escaped = false;
    while let Some(current) = source.get(index..).and_then(|rest| rest.chars().next()) {
        let next = index.saturating_add(current.len_utf8());
        index = next;
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some('\'') {
            if current == '\'' {
                quote = None;
            }
            continue;
        }
        if current == '\\' {
            escaped = true;
            continue;
        }
        if quote == Some('"') {
            if current == '"' {
                quote = None;
                continue;
            }
        } else if (single_quotes && current == '\'') || current == '"' {
            quote = Some(current);
            continue;
        }
        if current == '`' {
            let Some(rest) = source.get(next..) else {
                return;
            };
            let Some(end) = backtick_body_end(rest) else {
                return;
            };
            let Some(body) = rest.get(..end) else {
                return;
            };
            commands.push(body.to_owned());
            pending.push((body.to_owned(), QuotingLevel::Shell));
            index = next.saturating_add(end).saturating_add(1);
            continue;
        }
        if current != '$' {
            continue;
        }
        let Some(after) = source.get(next..).and_then(|rest| rest.strip_prefix('(')) else {
            continue;
        };
        if let Some(inner) = after.strip_prefix('(') {
            let Some(end) = arithmetic_command_end(inner) else {
                return;
            };
            let Some(body) = inner.get(..end) else {
                return;
            };
            pending.push((body.to_owned(), QuotingLevel::Arithmetic));
            index = next.saturating_add(end).saturating_add(4);
            continue;
        }
        let Some(end) = substitution_body_end(after) else {
            return;
        };
        let Some(body) = after.get(..end) else {
            return;
        };
        commands.push(body.to_owned());
        pending.push((body.to_owned(), QuotingLevel::Shell));
        index = next.saturating_add(end).saturating_add(2);
    }
}

fn substitution_body_end(body: &str) -> Option<usize> {
    let mut quote = None;
    let mut escaped = false;
    let mut depth = 0_u32;
    for (offset, current) in body.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some('\'') {
            if current == '\'' {
                quote = None;
            }
            continue;
        }
        if current == '\\' {
            escaped = true;
        } else if let Some(active) = quote {
            if current == active {
                quote = None;
            }
        } else if current == '\'' || current == '"' {
            quote = Some(current);
        } else if current == '(' {
            depth = depth.saturating_add(1);
        } else if current == ')' {
            if depth == 0 {
                return Some(offset);
            }
            depth -= 1;
        }
    }
    None
}

fn backtick_body_end(body: &str) -> Option<usize> {
    let mut escaped = false;
    for (offset, current) in body.char_indices() {
        if escaped {
            escaped = false;
        } else if current == '\\' {
            escaped = true;
        } else if current == '`' {
            return Some(offset);
        }
    }
    None
}

/// Offset of the `))` that closes one arithmetic expression.
///
/// Two different phases read this text and they do not read it alike. Finding the closing `))` is
/// tokenization, and the tokenizer honours single quotes, so `(( x = '(' ))` parses and the
/// quoted parenthesis takes no part in the depth count. Evaluation is the later phase, and there
/// the expression behaves as if it were double-quoted, which is what
/// [`QuotingLevel::Arithmetic`] models when substitutions are lifted out of the same text. Making
/// this function ignore single quotes to match that scanner loses the closing `))` for a body
/// holding a quoted parenthesis, and a lost terminator discards everything after the arithmetic
/// unexamined.
fn arithmetic_command_end(body: &str) -> Option<usize> {
    let mut characters = body.char_indices().peekable();
    let mut quote = None;
    let mut escaped = false;
    let mut depth = 0_u32;
    while let Some((offset, current)) = characters.next() {
        if escaped {
            escaped = false;
            continue;
        }
        if current == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if current == active {
                quote = None;
            }
            continue;
        }
        if current == '\'' || current == '"' {
            quote = Some(current);
        } else if current == '(' {
            depth = depth.saturating_add(1);
        } else if current == ')' {
            if depth > 0 {
                depth -= 1;
            } else if characters
                .peek()
                .is_some_and(|(_, following)| *following == ')')
            {
                return Some(offset);
            }
        }
    }
    None
}

fn ambiguous_prefix(command: &str, offset: usize) -> ShellParse {
    let Some(prefix) = command.get(..offset).map(str::trim_end) else {
        return ShellParse::Ambiguous(ShellShape::default());
    };
    if prefix.is_empty() {
        return ShellParse::Ambiguous(ShellShape::default());
    }
    let cs: Vec<_> = prefix.chars().collect();
    let shape = match scan_tokens(&cs) {
        Ok(tokens) => match build_shape(tokens) {
            ShellParse::Parsed(shape) | ShellParse::Ambiguous(shape) => shape,
            ShellParse::PlainlyInvalid => ShellShape::default(),
        },
        Err(ShellParse::Parsed(shape) | ShellParse::Ambiguous(shape)) => shape,
        Err(ShellParse::PlainlyInvalid) => ShellShape::default(),
    };
    ShellParse::Ambiguous(shape)
}

fn unquoted_heredoc_marker(command: &str) -> Option<usize> {
    let mut characters = command.char_indices().peekable();
    let mut quote = None;
    let mut escaped = false;
    while let Some((offset, current)) = characters.next() {
        if escaped {
            escaped = false;
            continue;
        }
        if current == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if current == active {
                quote = None;
            }
            continue;
        }
        if current == '\'' || current == '"' {
            quote = Some(current);
        } else if current == '<'
            && characters
                .peek()
                .is_some_and(|(_, following)| *following == '<')
        {
            return Some(offset);
        }
    }
    None
}

fn remote_timeout_defect(shell: &ShellInput<'_>, shape: &ShellShape) -> bool {
    shell.timeout_ms.is_none_or(|timeout| timeout == 0)
        && shape.commands.iter().any(has_remote_transport)
        && (shape
            .connectors
            .iter()
            .any(|connector| *connector != Connector::Pipe)
            || shape
                .commands
                .iter()
                .any(|command| has_remote_transport(command) && !has_stage_timeout(command)))
}

fn has_stage_timeout(command: &SimpleCommand) -> bool {
    timeout_payload_index(&command.words).is_some()
}

fn timeout_payload_index(words: &[Word]) -> Option<usize> {
    if words
        .first()
        .is_none_or(|word| basename(&word.text) != "timeout")
    {
        return None;
    }
    let mut index = 1;
    while let Some(word) = words.get(index) {
        match word.text.as_str() {
            "--" => {
                index += 1;
                break;
            }
            "--foreground" | "--preserve-status" => index += 1,
            "-k" | "--kill-after" | "-s" | "--signal" => {
                words.get(index + 1)?;
                index += 2;
            }
            option
                if option.starts_with("--kill-after=")
                    || option.starts_with("--signal=")
                    || (option.starts_with("-k") && option.len() > 2)
                    || (option.starts_with("-s") && option.len() > 2) =>
            {
                index += 1;
            }
            option if option.starts_with('-') => return None,
            _ => break,
        }
    }
    if positive_timeout_duration(&words.get(index)?.text) {
        words.get(index + 1).map(|_| index + 1)
    } else {
        None
    }
}

fn positive_timeout_duration(value: &str) -> bool {
    let number = value
        .strip_suffix('s')
        .or_else(|| value.strip_suffix('m'))
        .or_else(|| value.strip_suffix('h'))
        .or_else(|| value.strip_suffix('d'))
        .unwrap_or(value);
    number
        .parse::<f64>()
        .is_ok_and(|duration| duration.is_finite() && duration > 0.0)
}

fn has_remote_transport(command: &SimpleCommand) -> bool {
    let Some(index) = program_index(command) else {
        return false;
    };
    let Some(program) = command.words.get(index) else {
        return false;
    };
    matches!(basename(&program.text), "ssh" | "scp" | "sftp")
        || (basename(&program.text) == "rsync"
            && command
                .words
                .iter()
                .skip(index.saturating_add(1))
                .any(|word| remote_operand(&word.text)))
}

fn remote_operand(word: &str) -> bool {
    let Some((host, path)) = word.split_once(':') else {
        return false;
    };
    !host.is_empty() && !path.is_empty() && !host.contains('/')
}

fn background_contract_defect(shell: &ShellInput<'_>, shape: &ShellShape) -> bool {
    let detached = shell.declared_background == Some(true)
        || shape.connectors.contains(&Connector::Background)
        || shape.commands.iter().any(has_detaching_program);
    if !detached {
        return false;
    }
    let declared = shell.declared_background == Some(true);
    let startup_timeout = shell.timeout_ms.is_some_and(|timeout| timeout > 0);
    let stable_identity = shape.commands.iter().any(|command| {
        has_option_value(command, &["--job-id", "--pid-file", "--name"])
            || command.words.iter().any(|word| word.text.contains(".pid"))
    });
    let append_only_log = shape.commands.iter().any(|command| {
        command.redirects.iter().any(|redirect| {
            redirect.kind == RedirectKind::Append
                && !redirect.target.text.is_empty()
                && redirect.target.text != "/dev/null"
        })
    });
    let completion_marker = shape
        .commands
        .iter()
        .any(|command| has_option_value(command, &["--completion-marker"]));
    let supervised_status = shape
        .commands
        .iter()
        .any(|command| has_option_value(command, &["--status-cmd", "--supervised-status"]));
    !(declared
        && startup_timeout
        && stable_identity
        && append_only_log
        && completion_marker
        && supervised_status)
}

fn timing_defect(shape: &ShellShape) -> bool {
    timing_defect_at_depth(shape, false, 0)
}

fn timed_at_boundary(command: &SimpleCommand) -> bool {
    let Some(gate) = gate_index(command) else {
        return true;
    };
    timed_before(command, gate)
}

fn timed_before(command: &SimpleCommand, boundary: usize) -> bool {
    command
        .words
        .iter()
        .take(boundary)
        .enumerate()
        .any(|(index, word)| {
            is_time_word(&word.text)
                && command
                    .words
                    .iter()
                    .take(index)
                    .all(|prefix| wrapper_prefix_word(&prefix.text))
        })
}

fn timing_defect_at_depth(shape: &ShellShape, inherited_timing: bool, depth: usize) -> bool {
    const MAX_NESTED_SHELL_DEPTH: usize = 8;
    shape.commands.iter().any(|command| {
        if is_gate(command) && !inherited_timing && !timed_at_boundary(command) {
            return true;
        }
        if depth == MAX_NESTED_SHELL_DEPTH {
            return false;
        }
        let Some(payload) = nested_shell_payload(command) else {
            return false;
        };
        let ShellParse::Parsed(nested) = tokenize(&payload) else {
            return false;
        };
        let wrapper_timing = program_index(command)
            .is_some_and(|program| inherited_timing || timed_before(command, program));
        timing_defect_at_depth(&nested, wrapper_timing, depth + 1)
    })
}

fn wrapper_prefix_word(word: &str) -> bool {
    let base = basename(word);
    matches!(
        base,
        "timeout"
            | "env"
            | "command"
            | "nohup"
            | "setsid"
            | "nice"
            | "chrt"
            | "ionice"
            | "sudo"
            | "doas"
    ) || word.starts_with('-')
        || word.contains('=')
        || word.chars().all(|current| current.is_ascii_digit())
}

fn is_time_word(word: &str) -> bool {
    basename(word) == "time"
}

fn mutating_batch_defect(shape: &ShellShape) -> bool {
    operational_objectives(shape, 0) > 1
}

fn operational_objectives(shape: &ShellShape, depth: usize) -> usize {
    const MAX_NESTED_SHELL_DEPTH: usize = 8;
    shape
        .commands
        .iter()
        .map(|command| {
            let own = usize::from(operational_kind(command).is_some());
            if depth == MAX_NESTED_SHELL_DEPTH {
                return own;
            }
            let nested = nested_shell_payload(command)
                .and_then(|payload| match tokenize(&payload) {
                    ShellParse::Parsed(nested) => Some(operational_objectives(&nested, depth + 1)),
                    ShellParse::PlainlyInvalid | ShellParse::Ambiguous(_) => None,
                })
                .unwrap_or(0);
            if nested > 0 && command.redirects.iter().any(redirect_mutates) {
                nested
            } else {
                own + nested
            }
        })
        .sum()
}

fn pipeline_status_defect(shape: &ShellShape, nested: &[ShellShape]) -> bool {
    std::iter::once(shape).chain(nested).any(|candidate| {
        candidate
            .connectors
            .iter()
            .enumerate()
            .any(|(index, connector)| {
                *connector == Connector::Pipe
                    && candidate
                        .commands
                        .get(index)
                        .is_some_and(|command| operational_kind(command).is_some())
                    && !pipeline_status_preserved(candidate, index)
            })
    })
}

fn pipeline_status_preserved(shape: &ShellShape, pipeline_start: usize) -> bool {
    let pipefail_precedes = shape
        .commands
        .iter()
        .take(pipeline_start)
        .any(pipefail_enabled);
    let mut pipeline_end = pipeline_start + 1;
    while shape.connectors.get(pipeline_end) == Some(&Connector::Pipe) {
        pipeline_end += 1;
    }
    let producer_status_follows = shape
        .commands
        .iter()
        .skip(pipeline_end.saturating_add(1))
        .any(|command| {
            command.words.iter().any(|word| {
                word.text.contains("${PIPESTATUS[") || word.text.contains("$PIPESTATUS")
            })
        });
    pipefail_precedes || producer_status_follows
}

fn pipefail_enabled(command: &SimpleCommand) -> bool {
    command.words.first().is_some_and(|word| word.text == "set")
        && (command
            .words
            .windows(2)
            .any(|words| matches!(words, [option, value] if option.text == "-o" && value.text == "pipefail"))
            || command.words.windows(2).any(|words| {
                matches!(words, [option, value] if option.text.starts_with('-')
                    && option.text.contains('o')
                    && value.text == "pipefail")
            }))
}

fn destructive_operand_defect(shape: &ShellShape, nested: &[ShellShape], cwd: &str) -> bool {
    std::iter::once(shape)
        .chain(nested)
        .flat_map(|candidate| &candidate.commands)
        .any(|command| {
            destructive_operands(command).is_some_and(|operands| {
                operands.is_empty() || operands.iter().any(|word| unbounded_operand(word, cwd))
            })
        })
}

fn destructive_operands(command: &SimpleCommand) -> Option<Vec<&Word>> {
    let index = destructive_program_index(command)?;
    let program = basename(&command.words.get(index)?.text);
    if matches!(program, "rm" | "rmdir" | "shred" | "unlink") {
        return Some(
            command
                .words
                .iter()
                .skip(index.saturating_add(1))
                .filter(|word| !word.text.starts_with('-'))
                .collect(),
        );
    }
    if program == "truncate" {
        return Some(
            command
                .words
                .iter()
                .skip(index.saturating_add(1))
                .filter(|word| {
                    !word.text.starts_with('-') && !word.text.chars().all(char::is_numeric)
                })
                .collect(),
        );
    }
    if program == "find" && command.words.iter().any(|word| word.text == "-delete") {
        return Some(command.words.get(index + 1).into_iter().collect());
    }
    if program == "git" {
        let subcommand = git_subcommand_index(command, index)?;
        let name = command.words.get(subcommand)?.text.as_str();
        let arguments = command.words.get(subcommand.saturating_add(1)..)?;
        if name == "clean" && git_clean_is_dry_run(arguments) {
            return None;
        }
        if name == "clean"
            || (name == "reset" && arguments.iter().any(|word| word.text == "--hard"))
        {
            return Some(
                arguments
                    .iter()
                    .filter(|word| !word.text.starts_with('-'))
                    .collect(),
            );
        }
    }
    None
}

fn git_clean_is_dry_run(arguments: &[Word]) -> bool {
    arguments
        .iter()
        .any(|word| matches!(word.text.as_str(), "-n" | "--dry-run"))
}

fn destructive_program_index(command: &SimpleCommand) -> Option<usize> {
    let index = if shell_keyword_head(command)
        || command
            .words
            .first()
            .is_some_and(|word| matches!(word.text.as_str(), "!" | "exec" | "coproc"))
    {
        recovered_command_head(command)?
    } else {
        program_index(command)?
    };
    command.words.get(index).and_then(|word| {
        matches!(
            basename(&word.text),
            "rm" | "rmdir" | "shred" | "unlink" | "truncate" | "find" | "git"
        )
        .then_some(index)
    })
}

fn recovered_command_head(command: &SimpleCommand) -> Option<usize> {
    let head = command.words.first()?.text.as_str();
    match head {
        "while" | "until" | "if" | "then" | "do" | "else" | "{" | "!" | "exec" | "coproc" => {
            command.words.get(1).map(|_| 1)
        }
        "function" => command
            .words
            .iter()
            .position(|word| word.text == "{")
            .and_then(|index| command.words.get(index + 1).map(|_| index + 1)),
        _ => None,
    }
}

fn unbounded_operand(word: &Word, cwd: &str) -> bool {
    let value = word.text.as_str();
    value.is_empty()
        || word.substitution
        || value.contains('$')
        || value.contains('*')
        || value.contains('?')
        || value.contains('[')
        || value == "."
        || value == ".."
        || value == "/"
        || Path::new(value)
            .components()
            .any(|part| part.as_os_str() == "..")
        || broad_root(value, cwd)
}

fn broad_root(value: &str, cwd: &str) -> bool {
    let absolute_is_broad = Path::new(value).is_absolute()
        && Path::new(value)
            .components()
            .filter(|component| matches!(component, Component::Normal(_)))
            .count()
            <= 2;
    let home_relative_is_broad = ["~", "$HOME", "${HOME}"].iter().any(|root| {
        value == *root
            || value.strip_prefix(&format!("{root}/")).is_some_and(|tail| {
                tail.split('/')
                    .filter(|component| !component.is_empty())
                    .count()
                    <= 1
            })
    });
    let project_root = value.trim_end_matches('/') == cwd.trim_end_matches('/');
    absolute_is_broad || home_relative_is_broad || project_root
}

fn remote_privilege_defect(shape: &ShellShape) -> bool {
    shape.commands.iter().any(|command| {
        let Some(ssh_index) = program_index(command).filter(|index| {
            command
                .words
                .get(*index)
                .is_some_and(|word| basename(&word.text) == "ssh")
        }) else {
            return false;
        };
        let Some(destination_index) = ssh_destination(command, ssh_index) else {
            return false;
        };
        let payload_text = command
            .words
            .iter()
            .skip(destination_index.saturating_add(1))
            .map(|word| word.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let ShellParse::Parsed(payload_shape) = tokenize(&payload_text) else {
            return false;
        };
        let privileged_commands: Vec<_> = payload_shape
            .commands
            .iter()
            .filter_map(|nested| privilege_wrapper_index(nested).map(|index| (nested, index)))
            .collect();
        if privileged_commands.is_empty() {
            return false;
        }
        let Some(destination) = command.words.get(destination_index).map(|word| &word.text) else {
            return false;
        };
        let alias = is_alias(destination);
        let batch = ssh_option_is(command, "BatchMode", "yes");
        let privilege_noninteractive = privileged_commands.iter().all(|(nested, index)| {
            privilege_command_index(nested, *index)
                .is_some_and(|(_, noninteractive)| noninteractive)
        });
        !(alias && batch && privilege_noninteractive)
    })
}

#[derive(Default)]
struct NestedShells {
    parsed: Vec<ShellShape>,
    recovered: Vec<ShellShape>,
    plainly_invalid: bool,
    ambiguous: bool,
}

fn ambiguous_hygiene_defect(
    shell: &ShellInput<'_>,
    shape: &ShellShape,
    nested: &NestedShells,
    cwd: &str,
) -> Option<HygieneRuleId> {
    let all_nested = || nested.parsed.iter().chain(&nested.recovered);
    if remote_timeout_defect(shell, shape)
        || all_nested().any(|candidate| remote_timeout_defect(shell, candidate))
    {
        return Some(HygieneRuleId::RemoteTimeout);
    }
    if background_contract_defect(shell, shape)
        || all_nested().any(|candidate| background_contract_defect(shell, candidate))
    {
        return Some(HygieneRuleId::BackgroundContract);
    }
    if timing_defect(shape) || nested.recovered.iter().any(timing_defect) {
        return Some(HygieneRuleId::ExecutionTiming);
    }
    let objectives = operational_objectives(shape, 0)
        + nested
            .recovered
            .iter()
            .map(|candidate| operational_objectives(candidate, 0))
            .sum::<usize>();
    if objectives > 1 {
        return Some(HygieneRuleId::OneObjective);
    }
    if pipeline_status_defect(shape, &nested.parsed)
        || nested
            .recovered
            .iter()
            .any(|candidate| pipeline_status_defect(candidate, &[]))
    {
        return Some(HygieneRuleId::PipelineStatus);
    }
    if destructive_operand_defect(shape, &nested.parsed, cwd)
        || destructive_operand_defect(shape, &nested.recovered, cwd)
    {
        return Some(HygieneRuleId::DestructiveOperands);
    }
    if remote_privilege_defect(shape) || all_nested().any(remote_privilege_defect) {
        return Some(HygieneRuleId::RemotePrivilege);
    }
    None
}

fn nested_shell_shapes(shape: &ShellShape) -> NestedShells {
    let mut nested = NestedShells::default();
    collect_nested_shells(shape, 0, &mut nested);
    nested
}

fn collect_nested_shells(shape: &ShellShape, depth: usize, nested: &mut NestedShells) {
    const MAX_NESTED_SHELL_DEPTH: usize = 8;
    if depth == MAX_NESTED_SHELL_DEPTH {
        nested.ambiguous = true;
        return;
    }
    let payloads = shape
        .commands
        .iter()
        .filter_map(nested_shell_payload)
        .chain(shape.arithmetic_substitutions.iter().cloned());
    for payload in payloads {
        if payload.is_empty() {
            continue;
        }
        match tokenize(&payload) {
            ShellParse::Parsed(parsed) => {
                collect_nested_shells(&parsed, depth + 1, nested);
                nested.parsed.push(parsed);
            }
            ShellParse::PlainlyInvalid => nested.plainly_invalid = true,
            ShellParse::Ambiguous(recovered) => {
                collect_nested_shells(&recovered, depth + 1, nested);
                nested.recovered.push(recovered);
                nested.ambiguous = true;
            }
        }
    }
}

fn nested_shell_payload(command: &SimpleCommand) -> Option<String> {
    let program = program_index(command)?;
    match basename(&command.words.get(program)?.text) {
        "ssh" => {
            let destination = ssh_destination(command, program)?;
            joined_words(command.words.get(destination.saturating_add(1)..)?)
        }
        "sh" | "bash" => {
            let payload = shell_command_payload(command, program)?;
            joined_words(command.words.get(payload..)?)
        }
        "xargs" => {
            let payload = xargs_command_index(command, program)?;
            joined_words(command.words.get(payload..)?)
        }
        "eval" => joined_words(command.words.get(program.saturating_add(1)..)?),
        _ => None,
    }
}

fn joined_words(words: &[Word]) -> Option<String> {
    (!words.is_empty()).then(|| {
        words
            .iter()
            .map(|word| word.text.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    })
}

fn shell_command_payload(command: &SimpleCommand, program: usize) -> Option<usize> {
    let bash = basename(&command.words.get(program)?.text) == "bash";
    let mut index = program + 1;
    while let Some(word) = command.words.get(index) {
        if word.text == "-c"
            || word
                .text
                .strip_prefix('-')
                .is_some_and(|options| !options.starts_with('-') && options.contains('c'))
        {
            return command.words.get(index + 1).map(|_| index + 1);
        }
        if bash && matches!(word.text.as_str(), "--rcfile" | "--init-file") {
            command.words.get(index + 1)?;
            index += 2;
            continue;
        }
        if bash
            && ["--rcfile=", "--init-file="]
                .iter()
                .any(|option| word.text.starts_with(option) && word.text.len() > option.len())
        {
            index += 1;
            continue;
        }
        if !word.text.starts_with('-') {
            return None;
        }
        index += 1;
    }
    None
}

fn xargs_command_index(command: &SimpleCommand, program: usize) -> Option<usize> {
    let index = skip_options(
        command,
        program + 1,
        &[
            "-a",
            "--arg-file",
            "-E",
            "--eof",
            "-I",
            "--replace",
            "-L",
            "--max-lines",
            "-n",
            "--max-args",
            "-P",
            "--max-procs",
            "-s",
            "--max-chars",
        ],
    );
    command.words.get(index).map(|_| index)
}

fn ssh_destination(command: &SimpleCommand, ssh_index: usize) -> Option<usize> {
    let mut index = ssh_index + 1;
    while let Some(word) = command.words.get(index).map(|word| &word.text) {
        if matches!(word.as_str(), "-o" | "-F" | "-i" | "-J" | "-l" | "-p") {
            index += 2;
        } else if word.starts_with('-') {
            index += 1;
        } else {
            return Some(index);
        }
    }
    None
}

fn ssh_option_is(command: &SimpleCommand, name: &str, value: &str) -> bool {
    let expected = format!("{name}={value}");
    command.words.iter().enumerate().any(|(index, word)| {
        word.text == format!("-o{expected}")
            || (word.text == "-o"
                && command
                    .words
                    .get(index + 1)
                    .is_some_and(|next| next.text == expected))
    })
}

fn is_alias(destination: &str) -> bool {
    !destination.is_empty()
        && !destination.contains(['@', '.', ':', '/'])
        && destination
            .chars()
            .all(|current| current.is_ascii_alphanumeric() || current == '-')
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OperationalKind {
    Gate,
    Mutation,
}

fn operational_kind(command: &SimpleCommand) -> Option<OperationalKind> {
    if is_gate(command) {
        Some(OperationalKind::Gate)
    } else if is_mutation(command) {
        Some(OperationalKind::Mutation)
    } else {
        None
    }
}

fn is_gate(command: &SimpleCommand) -> bool {
    gate_index(command).is_some()
}

fn gate_index(command: &SimpleCommand) -> Option<usize> {
    let index = program_index(command)?;
    let word = command.words.get(index)?;
    let base = basename(&word.text);
    if informational_gate_arguments(base, command.words.get(index.saturating_add(1)..)?) {
        return None;
    }
    let next = command
        .words
        .get(index + 1)
        .map(|value| value.text.as_str());
    let following = command
        .words
        .get(index + 2)
        .map(|value| value.text.as_str());
    let subcommand_gate = next.is_some_and(|subcommand| {
        gate_subcommand(base, subcommand)
            && (base != "npm" || subcommand != "run" || following.is_some())
    });
    let direct_gate = matches!(
        base,
        "cargo-fmt"
            | "clippy"
            | "pytest"
            | "ninja"
            | "make"
            | "superloop-lint"
            | "gradle"
            | "mvn"
            | "tsc"
    );
    (subcommand_gate || direct_gate).then_some(index)
}

fn informational_gate_arguments(program: &str, arguments: &[Word]) -> bool {
    let Some(information) = arguments
        .iter()
        .position(|word| informational_argument(&word.text))
    else {
        return false;
    };
    let positional: Vec<_> = arguments
        .iter()
        .enumerate()
        .filter(|(_, word)| !word.text.starts_with('-'))
        .collect();
    if arguments
        .get(information)
        .is_some_and(|word| !word.text.starts_with('-'))
    {
        return positional.len() == 1;
    }
    positional.is_empty()
        || (positional.len() == 1
            && arguments
                .first()
                .is_some_and(|word| gate_subcommand(program, &word.text)))
}

fn informational_argument(argument: &str) -> bool {
    matches!(
        argument,
        "--version"
            | "-V"
            | "-version"
            | "--help"
            | "-h"
            | "help"
            | "--list"
            | "--list-only"
            | "--list-tests"
            | "--listFilesOnly"
            | "tasks"
            | "projects"
    ) || argument.starts_with("help:")
}

fn gate_subcommand(program: &str, subcommand: &str) -> bool {
    match program {
        "cargo" => matches!(
            subcommand,
            "bench"
                | "build"
                | "check"
                | "clippy"
                | "doc"
                | "fmt"
                | "install"
                | "nextest"
                | "run"
                | "test"
        ),
        "go" => matches!(subcommand, "build" | "test" | "vet"),
        "cmake" => subcommand == "--build",
        "npm" => matches!(subcommand, "ci" | "install" | "run" | "test"),
        "pnpm" | "yarn" => matches!(subcommand, "install" | "test" | "run"),
        "pip" | "pip3" | "dnf" | "apt-get" | "apt" => subcommand == "install",
        "docker" | "podman" => subcommand == "build",
        "meson" => matches!(subcommand, "setup" | "compile" | "test"),
        _ => false,
    }
}

fn is_mutation(command: &SimpleCommand) -> bool {
    let Some(index) = program_index(command) else {
        return false;
    };
    let Some(program) = command.words.get(index).map(|word| basename(&word.text)) else {
        return false;
    };
    if [
        "rm", "rmdir", "shred", "unlink", "truncate", "mv", "cp", "install", "mkdir", "touch",
        "chmod", "chown", "tee",
    ]
    .contains(&program)
    {
        return true;
    }
    (program == "git" && {
        git_subcommand_index(command, index).is_some_and(|subcommand| {
            command.words.get(subcommand).is_some_and(|word| {
                matches!(
                    word.text.as_str(),
                    "add"
                        | "checkout"
                        | "clean"
                        | "commit"
                        | "merge"
                        | "mv"
                        | "pull"
                        | "push"
                        | "rebase"
                        | "reset"
                        | "restore"
                        | "rm"
                        | "switch"
                        | "tag"
                )
            })
        })
    }) || command.redirects.iter().any(redirect_mutates)
}

fn redirect_mutates(redirect: &Redirect) -> bool {
    matches!(redirect.kind, RedirectKind::Write | RedirectKind::Append)
        && redirect.target.text != "/dev/null"
}

fn program_index(command: &SimpleCommand) -> Option<usize> {
    if informational_command_query(command) {
        return Some(0);
    }
    program_index_from(command, 0)
}

fn informational_command_query(command: &SimpleCommand) -> bool {
    matches!(
        command.words.as_slice(),
        [program, option, subject]
            if basename(&program.text) == "command"
                && option.text == "-v"
                && !subject.text.starts_with('-')
    )
}

fn git_subcommand_index(command: &SimpleCommand, git: usize) -> Option<usize> {
    let mut index = git + 1;
    while let Some(word) = command.words.get(index) {
        if word.text == "--" {
            return command.words.get(index + 1).map(|_| index + 1);
        }
        if !word.text.starts_with('-') || word.text == "-" {
            return Some(index);
        }
        let consumes_value = matches!(
            word.text.as_str(),
            "-C" | "-c"
                | "--git-dir"
                | "--work-tree"
                | "--namespace"
                | "--exec-path"
                | "--config-env"
        );
        index += 1 + usize::from(consumes_value);
    }
    None
}

fn program_index_from(command: &SimpleCommand, start: usize) -> Option<usize> {
    let mut index = start;
    while command
        .words
        .get(index)
        .is_some_and(|word| assignment_word(&word.text))
    {
        index += 1;
    }
    loop {
        let program = basename(&command.words.get(index)?.text);
        match program {
            "env" => {
                index += 1;
                index = skip_options(command, index, &["-u", "--unset", "-C", "--chdir"]);
                while command
                    .words
                    .get(index)
                    .is_some_and(|word| assignment_word(&word.text))
                {
                    index += 1;
                }
            }
            "time" => {
                index += 1;
                index = skip_options(command, index, &["-f", "--format", "-o", "--output"]);
            }
            "nice" => {
                index += 1;
                index = skip_options(command, index, &["-n", "--adjustment"]);
            }
            "command" | "nohup" | "setsid" => {
                index += 1;
                index = skip_options(command, index, &[]);
            }
            "chrt" => {
                index += 1;
                index = skip_options(
                    command,
                    index,
                    &[
                        "-T",
                        "--sched-runtime",
                        "-P",
                        "--sched-period",
                        "-D",
                        "--sched-deadline",
                    ],
                );
                if command
                    .words
                    .get(index)
                    .is_some_and(|word| word.text.parse::<u64>().is_ok())
                {
                    index += 1;
                }
            }
            "ionice" => {
                index += 1;
                index = skip_options(
                    command,
                    index,
                    &[
                        "-c",
                        "--class",
                        "-n",
                        "--classdata",
                        "-p",
                        "--pid",
                        "-P",
                        "--pgid",
                        "-u",
                        "--uid",
                    ],
                );
            }
            "timeout" => {
                index += 1;
                index = skip_options(command, index, &["-k", "--kill-after", "-s", "--signal"]);
                index += 1;
            }
            "sudo" | "doas" => {
                index = privilege_command_index(command, index)?.0;
            }
            _ => return Some(index),
        }
    }
}

fn skip_options(command: &SimpleCommand, mut index: usize, valued: &[&str]) -> usize {
    while let Some(word) = command.words.get(index) {
        if word.text == "--" {
            return index + 1;
        }
        if !word.text.starts_with('-') || word.text == "-" {
            return index;
        }
        let consumes_value = valued.contains(&word.text.as_str());
        index += 1 + usize::from(consumes_value);
    }
    index
}

fn privilege_command_index(command: &SimpleCommand, wrapper: usize) -> Option<(usize, bool)> {
    let program = basename(&command.words.get(wrapper)?.text);
    let valued: &[&str] = if program == "sudo" {
        &[
            "-u",
            "--user",
            "-g",
            "--group",
            "-h",
            "--host",
            "-p",
            "--prompt",
            "-C",
            "--close-from",
            "-R",
            "--chroot",
            "-D",
            "--chdir",
            "-r",
            "--role",
            "-t",
            "--type",
        ]
    } else {
        &["-C", "-u"]
    };
    let mut index = wrapper + 1;
    let mut noninteractive = false;
    while let Some(word) = command.words.get(index) {
        if word.text == "--" {
            return command
                .words
                .get(index + 1)
                .map(|_| (index + 1, noninteractive));
        }
        if !word.text.starts_with('-') || word.text == "-" {
            return Some((index, noninteractive));
        }
        noninteractive |= word.text == "--non-interactive"
            || word
                .text
                .strip_prefix('-')
                .is_some_and(|options| !options.starts_with('-') && options.contains('n'));
        let consumes_value = valued.contains(&word.text.as_str());
        index += 1 + usize::from(consumes_value);
    }
    None
}

fn privilege_wrapper_index(command: &SimpleCommand) -> Option<usize> {
    command
        .words
        .iter()
        .enumerate()
        .take(program_index(command).unwrap_or(command.words.len()))
        .find_map(|(index, word)| matches!(basename(&word.text), "sudo" | "doas").then_some(index))
}

fn has_detaching_program(command: &SimpleCommand) -> bool {
    let program = program_index(command).unwrap_or(command.words.len());
    command
        .words
        .iter()
        .take(program.saturating_add(1))
        .any(|word| matches!(basename(&word.text), "nohup" | "disown" | "setsid"))
}

fn assignment_word(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && name
                .chars()
                .all(|current| current == '_' || current.is_ascii_alphanumeric())
    })
}

fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

fn has_option_value(command: &SimpleCommand, options: &[&str]) -> bool {
    command.words.iter().enumerate().any(|(index, word)| {
        (options.contains(&word.text.as_str())
            && command
                .words
                .get(index + 1)
                .is_some_and(|value| !value.text.is_empty() && !value.text.starts_with('-')))
            || options.iter().any(|option| {
                word.text
                    .strip_prefix(&format!("{option}="))
                    .is_some_and(|value| !value.is_empty())
            })
    })
}

fn native_read_matches(input: &Map<String, Value>) -> bool {
    input
        .get("file_path")
        .and_then(Value::as_str)
        .is_some_and(project_path)
        && optional_nonnegative_integer(input, "offset")
        && optional_nonnegative_integer(input, "limit")
}

fn native_glob_matches(input: &Map<String, Value>) -> bool {
    input
        .get("pattern")
        .and_then(Value::as_str)
        .is_some_and(|pattern| !pattern.is_empty() && !escapes_project(pattern))
        && optional_project_path(input, "path")
}

fn native_grep_matches(input: &Map<String, Value>) -> bool {
    input
        .get("pattern")
        .and_then(Value::as_str)
        .is_some_and(|pattern| !pattern.is_empty())
        && optional_project_path(input, "path")
        && input
            .get("path")
            .and_then(Value::as_str)
            .is_none_or(|path| !sensitive_value(path))
}

fn native_web_search_matches(input: &Map<String, Value>) -> bool {
    input
        .get("query")
        .and_then(Value::as_str)
        .is_some_and(|query| !query.is_empty() && !credential_shaped(query))
}

fn native_web_fetch_matches(input: &Map<String, Value>) -> bool {
    let valid_url = input.get("url").and_then(Value::as_str).is_some_and(|url| {
        (url.starts_with("https://") || url.starts_with("http://"))
            && !credential_shaped(url)
            && url.split_once("//").is_none_or(|(_, authority)| {
                !authority
                    .split('/')
                    .next()
                    .unwrap_or_default()
                    .contains('@')
            })
    });
    let get_only = input
        .get("method")
        .is_none_or(|method| method.as_str() == Some("GET"));
    valid_url
        && get_only
        && !input.contains_key("body")
        && !input.contains_key("upload")
        && !input.contains_key("file")
}

fn optional_nonnegative_integer(input: &Map<String, Value>, field: &str) -> bool {
    input
        .get(field)
        .is_none_or(|value| value.as_u64().is_some())
}

fn optional_project_path(input: &Map<String, Value>, field: &str) -> bool {
    input
        .get(field)
        .is_none_or(|value| value.as_str().is_some_and(project_path))
}

fn project_path(value: &str) -> bool {
    !value.is_empty() && !escapes_project(value) && !sensitive_value(value)
}

fn escapes_project(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with('~')
        || value.contains('$')
        || value.contains("$(")
        || Path::new(value)
            .components()
            .any(|part| part.as_os_str() == "..")
}

fn sensitive_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.split(['/', '\\']).any(sensitive_basename)
}

fn sensitive_basename(name: &str) -> bool {
    if name == ".ssh" {
        return true;
    }
    let stem = name
        .rsplit_once('.')
        .filter(|(candidate, _)| !candidate.is_empty())
        .map_or(name, |(candidate, _)| candidate);
    let sensitive = [
        "secret",
        "env",
        "credentials",
        "id_ed25519",
        "id_rsa",
        "private-key",
        "key",
        "token",
        "password",
    ];
    sensitive.iter().any(|token| {
        name == *token
            || name
                .strip_prefix('.')
                .is_some_and(|tail| tail == *token || tail.starts_with(&format!("{token}.")))
            || stem == *token
            || ['_', '-', '.']
                .iter()
                .any(|separator| stem.ends_with(&format!("{separator}{token}")))
    }) || ["secret", "token", "password"].iter().any(|token| {
        let plural = format!("{token}s");
        stem == plural
            || ['_', '-', '.']
                .iter()
                .any(|separator| stem.ends_with(&format!("{separator}{plural}")))
            || ['_', '-', '.']
                .iter()
                .any(|separator| stem.starts_with(&format!("{token}{separator}")))
    }) || ["api_key", "api_keys", "api-key", "api-keys"]
        .iter()
        .any(|prefix| {
            stem == *prefix
                || ['_', '-', '.']
                    .iter()
                    .any(|separator| stem.starts_with(&format!("{prefix}{separator}")))
        })
}

fn credential_shaped(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("bearer ")
        || lower.contains("password=")
        || lower.contains("token=")
        || lower.contains("api_key=")
        || lower.contains("api-key=")
        || lower.contains("sk-")
}

fn shell_read_entry(shell: &ShellInput<'_>) -> Option<&'static str> {
    let ShellParse::Parsed(shape) = tokenize(shell.command) else {
        return None;
    };
    let command = shape.commands.first()?;
    if shape.commands.len() != 1
        || !shape.connectors.is_empty()
        || shape.has_subshell
        || !command.redirects.is_empty()
        || command.words.iter().any(|word| word.substitution)
    {
        return None;
    }
    if filesystem_observation(command) {
        Some("bash-filesystem-observation")
    } else if source_observation(command) {
        Some("bash-source-observation")
    } else if repository_observation(command) {
        Some("bash-repository-observation")
    } else {
        None
    }
}

fn filesystem_observation(command: &SimpleCommand) -> bool {
    let Some(program) = command.words.first().map(|word| basename(&word.text)) else {
        return false;
    };
    let Some(arguments) = command.words.get(1..) else {
        return false;
    };
    match program {
        "pwd" => arguments
            .iter()
            .all(|word| matches!(word.text.as_str(), "-L" | "-P")),
        "ls" => observation_arguments(arguments, "1AadlFh", false),
        "stat" => observation_arguments(arguments, "L", true),
        "file" => observation_arguments(arguments, "b", true),
        "readlink" => observation_arguments(arguments, "efmn", true),
        "wc" => observation_arguments(arguments, "clmw", true),
        _ => false,
    }
}

fn observation_arguments(arguments: &[Word], short_options: &str, require_path: bool) -> bool {
    let mut paths = 0_usize;
    let mut options_done = false;
    for word in arguments {
        if !options_done && word.text == "--" {
            options_done = true;
        } else if !options_done && word.text.starts_with('-') {
            if !word.text.strip_prefix('-').is_some_and(|options| {
                !options.is_empty() && options.chars().all(|option| short_options.contains(option))
            }) {
                return false;
            }
        } else if project_path(&word.text) {
            paths += 1;
            options_done = true;
        } else {
            return false;
        }
    }
    !require_path || paths > 0
}

fn source_observation(command: &SimpleCommand) -> bool {
    let Some(program) = command.words.first().map(|word| basename(&word.text)) else {
        return false;
    };
    let Some(arguments) = command.words.get(1..) else {
        return false;
    };
    match program {
        "rg" | "grep" => search_observation(arguments),
        "sed" => sed_observation(arguments),
        "head" | "tail" => head_tail_observation(arguments),
        "jq" => jq_observation(arguments),
        _ => false,
    }
}

fn search_observation(arguments: &[Word]) -> bool {
    let mut positional = Vec::new();
    for word in arguments {
        if matches!(
            word.text.as_str(),
            "-n" | "-F" | "--fixed-strings" | "--line-number"
        ) {
            continue;
        }
        if word.text.starts_with('-') {
            return false;
        }
        positional.push(word.text.as_str());
    }
    !positional.is_empty()
        && positional.iter().skip(1).all(|path| project_path(path))
        && positional
            .first()
            .is_some_and(|pattern| !pattern.is_empty())
}

fn sed_observation(arguments: &[Word]) -> bool {
    matches!(arguments, [option, script, paths @ ..]
        if option.text == "-n"
            && script.text.ends_with('p')
            && !script.text.contains(['e', 'w'])
            && !paths.is_empty()
            && paths.iter().all(|word| project_path(&word.text)))
}

fn head_tail_observation(arguments: &[Word]) -> bool {
    match arguments {
        [path, rest @ ..] if !path.text.starts_with('-') => {
            project_path(&path.text) && rest.iter().all(|word| project_path(&word.text))
        }
        [option, count, paths @ ..] if option.text == "-n" => {
            count.text.parse::<u64>().is_ok()
                && !paths.is_empty()
                && paths.iter().all(|word| project_path(&word.text))
        }
        _ => false,
    }
}

fn jq_observation(arguments: &[Word]) -> bool {
    let [filter, paths @ ..] = arguments else {
        return false;
    };
    !paths.is_empty()
        && !filter.text.contains("system")
        && !filter.text.contains("$ENV")
        && paths.iter().all(|word| project_path(&word.text))
}

fn repository_observation(command: &SimpleCommand) -> bool {
    if command
        .words
        .first()
        .is_none_or(|word| basename(&word.text) != "git")
    {
        return false;
    }
    let Some(subcommand) = git_subcommand_index(command, 0) else {
        return false;
    };
    if !command.words.get(subcommand).is_some_and(|word| {
        matches!(
            word.text.as_str(),
            "status" | "diff" | "log" | "show" | "rev-parse"
        )
    }) {
        return false;
    }
    command
        .words
        .iter()
        .skip(1)
        .take(subcommand.saturating_sub(1))
        .chain(command.words.iter().skip(subcommand.saturating_add(1)))
        .all(|word| {
            !forbidden_git_read_option(&word.text)
                && (word.text.starts_with('-') || word.text == "--" || project_path(&word.text))
        })
}

fn forbidden_git_read_option(option: &str) -> bool {
    [
        "-C",
        "--git-dir",
        "--work-tree",
        "--output",
        "--ext-diff",
        "--no-index",
    ]
    .iter()
    .any(|forbidden| {
        option == *forbidden
            || option
                .strip_prefix(forbidden)
                .is_some_and(|suffix| suffix.starts_with('='))
            || (*forbidden == "-C" && option.starts_with("-C") && option.len() > 2)
    })
}

/// Bounded shell tokens used by the hook's scope validator; no filesystem or environment access.
#[must_use]
pub fn scope_words(command: &str) -> Option<Vec<String>> {
    scope_words_at_depth(command, 0)
}

fn scope_words_at_depth(command: &str, depth: u8) -> Option<Vec<String>> {
    if depth >= 8 {
        return None;
    }
    let ShellParse::Parsed(shape) = tokenize(command) else {
        return None;
    };
    if shape.has_subshell || !shape.arithmetic_substitutions.is_empty() {
        return None;
    }
    let mut words = Vec::new();
    for simple in shape.commands {
        let program = program_index(&simple)?;
        let emits_data = simple
            .words
            .get(program)
            .is_some_and(|word| matches!(basename(&word.text), "printf" | "echo"));
        let nested = nested_shell_payload(&simple);
        if let Some(payload) = &nested {
            words.extend(scope_words_at_depth(payload, depth + 1)?);
        }
        for (index, word) in simple.words.into_iter().enumerate() {
            if word.substitution || word.text.contains(['$', '`', '*', '?']) {
                return None;
            }
            if (emits_data && index > program)
                || (nested.is_some() && word.text.contains(char::is_whitespace))
            {
                continue;
            }
            words.push(word.text);
        }
        for redirect in simple.redirects {
            if redirect.target.substitution || redirect.target.text.contains(['$', '`', '*', '?']) {
                return None;
            }
            words.push(redirect.target.text);
        }
    }
    Some(words)
}
