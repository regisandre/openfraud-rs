//! Tests that set environment variables (secrets read by name). They run in
//! their own process so no other theme can observe the variables.

#[path = "../it/support.rs"]
mod support;

mod alerts;
mod stripe;
