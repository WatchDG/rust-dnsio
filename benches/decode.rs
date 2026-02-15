use criterion::{Criterion, black_box, criterion_group, criterion_main};
use dnsio::{decode_message, decode_message_ref};

/// Minimal valid DNS query: example.com A IN
fn sample_dns_message() -> Vec<u8> {
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

fn bench_decode_message_ref(c: &mut Criterion) {
    let data = sample_dns_message();

    c.bench_function("decode_message_ref", |b| {
        b.iter(|| {
            let msg_ref = decode_message_ref(black_box(&data)).unwrap();
            black_box(msg_ref);
        })
    });
}

fn bench_decode_message(c: &mut Criterion) {
    let data = sample_dns_message();

    c.bench_function("decode_message", |b| {
        b.iter(|| {
            let msg = decode_message(black_box(&data)).unwrap();
            black_box(msg);
        })
    });
}

fn bench_decode_message_via_ref(c: &mut Criterion) {
    let data = sample_dns_message();

    c.bench_function("decode_message_via_ref", |b| {
        b.iter(|| {
            let msg_ref = decode_message_ref(black_box(&data)).unwrap();
            let msg = msg_ref.decode_message(black_box(&data)).unwrap();
            black_box(msg);
        })
    });
}

criterion_group!(
    benches,
    bench_decode_message_ref,
    bench_decode_message,
    bench_decode_message_via_ref
);
criterion_main!(benches);
