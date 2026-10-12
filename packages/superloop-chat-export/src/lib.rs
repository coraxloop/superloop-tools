#![doc = include_str!("../README.md")]

pub mod agents;
pub mod folder;
pub mod head;
pub mod input;
pub mod load;
pub mod markdown;
pub mod names;
pub mod output;
pub mod owner;
pub mod plan;
pub mod pool;
pub mod registry;
pub mod render;
pub mod templates;
pub mod tree;
pub mod view;

#[cfg(test)]
mod tests;
