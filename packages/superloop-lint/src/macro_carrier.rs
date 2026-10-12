// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Torrust project contributors

//! Source-written test items and explicit documentation attributes in macros.
//!
//! No expansion is performed. A test-bearing invocation supplies item syntax;
//! its parameter strategies are irrelevant to the census, so only parameter
//! groups are erased before parsing items. Original attribute and identifier
//! spans remain intact. A marked body that cannot be read refuses by name.

use proc_macro2::{Delimiter, Group, TokenStream, TokenTree};
use syn::{Expr, ExprLit, Lit, Meta};

use crate::census::{byte_offset, line_starts};

pub fn invocation(tokens: TokenStream) -> Result<Option<syn::File>, String> {
    let (tokens, marked) = normalize(tokens);
    if !marked {
        return Ok(None);
    }
    syn::parse2(tokens)
        .map(Some)
        .map_err(|error| format!("macro-doc-carrier: {error}"))
}

fn normalize(tokens: TokenStream) -> (TokenStream, bool) {
    let mut normalized = TokenStream::new();
    let mut marked = false;
    let mut hash = false;
    let mut parameters = false;
    let mut definition = false;
    for token in tokens {
        let next_hash =
            matches!(&token, TokenTree::Punct(punctuation) if punctuation.as_char() == '#');
        let token = match token {
            TokenTree::Ident(ref ident) if ident == "macro_rules" => {
                definition = true;
                token
            }
            TokenTree::Ident(ref ident) if ident == "fn" => {
                parameters = true;
                token
            }
            TokenTree::Group(group) => {
                if definition {
                    definition = false;
                    normalized.extend([TokenTree::Group(group)]);
                    continue;
                }
                if hash && group.delimiter() == Delimiter::Bracket {
                    marked |= syn::parse2::<Meta>(group.stream()).is_ok_and(|meta| {
                        meta.path()
                            .segments
                            .last()
                            .is_some_and(|segment| segment.ident == "test")
                    });
                }
                let inner = if parameters && group.delimiter() == Delimiter::Parenthesis {
                    parameters = false;
                    TokenStream::new()
                } else {
                    let (inner, nested) = normalize(group.stream());
                    marked |= nested;
                    inner
                };
                let mut replacement = Group::new(group.delimiter(), inner);
                replacement.set_span(group.span());
                TokenTree::Group(replacement)
            }
            token => token,
        };
        hash = next_hash;
        normalized.extend([token]);
    }
    (normalized, marked)
}

pub struct Document {
    pub start: usize,
    pub end: usize,
    pub text: String,
}

pub fn documents(source: &str) -> Vec<Document> {
    let Ok(tokens) = source.parse::<TokenStream>() else {
        return Vec::new();
    };
    let starts = line_starts(source);
    let mut documents = Vec::new();
    collect_documents(tokens, source, &starts, &mut documents);
    documents
}

fn collect_documents(
    tokens: TokenStream,
    source: &str,
    starts: &[usize],
    documents: &mut Vec<Document>,
) {
    let mut hash = None;
    let mut definition = false;
    for token in tokens {
        match token {
            TokenTree::Ident(ident) if ident == "macro_rules" => {
                definition = true;
            }
            TokenTree::Punct(punctuation) if punctuation.as_char() == '#' => {
                hash = Some(punctuation.span().start());
                continue;
            }
            TokenTree::Punct(punctuation) if punctuation.as_char() == '!' && hash.is_some() => {
                continue;
            }
            TokenTree::Group(group) => {
                if definition {
                    definition = false;
                    hash = None;
                    continue;
                }
                if let Some(position) = hash
                    && group.delimiter() == Delimiter::Bracket
                {
                    let start = byte_offset(source, starts, position.line, position.column);
                    // Doc comments become attributes in tokens too. Their original
                    // bytes are already read by the ordinary comment reader.
                    if source[start..].starts_with('#')
                        && let Some(text) = doc_text(&group)
                    {
                        let end = group.span().end();
                        documents.push(Document {
                            start: start + 2,
                            end: byte_offset(source, starts, end.line, end.column),
                            text,
                        });
                    }
                } else {
                    collect_documents(group.stream(), source, starts, documents);
                }
            }
            _ => {}
        }
        hash = None;
    }
}

fn doc_text(group: &Group) -> Option<String> {
    let Meta::NameValue(value) = syn::parse2::<Meta>(group.stream()).ok()? else {
        return None;
    };
    if !value.path.is_ident("doc") {
        return None;
    }
    match value.value {
        Expr::Lit(ExprLit {
            lit: Lit::Str(literal),
            ..
        }) => Some(literal.value()),
        _ => None,
    }
}
