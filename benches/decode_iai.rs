use dnsio::{decode_message, decode_message_ref};
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;

/// Minimal valid DNS query: example.com A IN
fn setup_sample_dns_message() -> Vec<u8> {
    vec![
        0x00, 0x01, // ID
        0x01, 0x00, // Flags: RD=1
        0x00, 0x01, // QDCOUNT=1
        0x00, 0x00, // ANCOUNT=0
        0x00, 0x00, // NSCOUNT=0
        0x00, 0x00, // ARCOUNT=0
        // QNAME: example.com
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
        0x03, b'c', b'o', b'm', // "com"
        0x00, // root
        // QTYPE=A, QCLASS=IN
        0x00, 0x01, 0x00, 0x01,
    ]
}

#[library_benchmark]
#[bench::with_data(setup = setup_sample_dns_message)]
fn bench_decode_message_ref(data: Vec<u8>) {
    black_box(decode_message_ref(black_box(&data)).unwrap());
}

#[library_benchmark]
#[bench::with_data(setup = setup_sample_dns_message)]
fn bench_decode_message(data: Vec<u8>) {
    black_box(decode_message(black_box(&data)).unwrap());
}

#[library_benchmark]
#[bench::with_data(setup = setup_sample_dns_message)]
fn bench_decode_message_via_ref(data: Vec<u8>) {
    let msg_ref = decode_message_ref(black_box(&data)).unwrap();
    black_box(msg_ref.decode_message(black_box(&data)).unwrap());
}

library_benchmark_group!(
    name = decode_group;
    benchmarks =
        bench_decode_message_ref,
        bench_decode_message,
        bench_decode_message_via_ref
);

main!(library_benchmark_groups = decode_group);
