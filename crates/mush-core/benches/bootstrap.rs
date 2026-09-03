// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Bootstrap line protocol: strict parsing of a typical `MUSH CONNECT`
//! line, and scanner throughput over login output.
//!
//! Neither is remotely performance-critical (each runs once per
//! session over at most a few hundred KB), but the scanner reads
//! attacker-influenced input, so its cost should be predictable and
//! linear.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use mush_core::bootstrap::{Connect, ConnectScanner, ScanLimits};
use mush_core::pinning::KeyPin;

/// A connect line of typical shape: version, port, key, two address
/// hints.
fn typical_connect_line() -> String {
  let connect = Connect {
    version: 1,
    udp_port: 60123,
    server_key: KeyPin::from_bytes([7u8; 32]),
    addr_hints: vec![
      "192.0.2.10:60123".parse().unwrap(),
      "[2001:db8::1]:60123".parse().unwrap(),
    ],
  };
  connect.to_wire()
}

/// Several megabytes of motd-shaped login output: banner text, lookalike
/// prefixes, binary junk, and blank lines, with no connect line.
fn motd_output(target_bytes: usize) -> Vec<u8> {
  let lines: [&[u8]; 6] = [
    b"Welcome to example.org (GNU/Linux 6.8.0-40-generic x86_64)\n",
    b" * Documentation:  https://help.example.org\n",
    b"MUSH CONNECTING to the mainframe...\n",
    b"Last login: Thu Aug 28 09:15:03 2026 from 192.0.2.99\n",
    b"binary junk: \xff\xfe\x00\x01 embedded\n",
    b"\n",
  ];
  let mut output = Vec::with_capacity(target_bytes + 64);
  while output.len() < target_bytes {
    for line in lines {
      output.extend_from_slice(line);
    }
  }
  output
}

fn bench_bootstrap(c: &mut Criterion) {
  let line = typical_connect_line();
  c.bench_function("bootstrap/connect_parse", |b| {
    b.iter(|| Connect::parse(black_box(&line)).unwrap());
  });

  let output = motd_output(4 * 1024 * 1024);
  // A scan budget the login output cannot exhaust: the interesting number is
  // scanning cost per byte, not budget enforcement.
  let limits = ScanLimits {
    max_lines: usize::MAX,
    max_bytes: usize::MAX,
  };
  let mut group = c.benchmark_group("bootstrap");
  group.throughput(Throughput::Bytes(output.len() as u64));
  group.bench_function("scanner_push_login_output", |b| {
    b.iter(|| {
      let mut scanner = ConnectScanner::new(limits);
      // Read-sized chunks, as the channel delivers them.
      for chunk in output.chunks(32 * 1024) {
        assert!(scanner.push(black_box(chunk)).unwrap().is_none());
      }
      scanner.bytes_seen()
    });
  });
  group.finish();
}

criterion_group!(benches, bench_bootstrap);
criterion_main!(benches);
