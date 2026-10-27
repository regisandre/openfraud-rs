//! One test binary for every theme that needs no process-wide state: a single
//! link step instead of one per file. Tests that set environment variables
//! live in `tests/env` and keep their own process.

mod support;

mod agent;
mod ai;
mod api;
mod cli;
mod compliance;
mod config;
mod decision;
mod device;
mod engine;
mod event;
mod expr;
mod geo;
mod graph;
mod keys;
mod lists;
mod networks;
mod outbox;
mod replay;
mod run;
mod safety;
mod scenarios;
mod signals;
mod webhook;
mod window;
