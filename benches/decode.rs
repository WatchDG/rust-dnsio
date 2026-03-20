use criterion::{Criterion, criterion_group, criterion_main};
use dnsio::{decode_message, decode_message_ref, MessageBuilder, MessageRefBuilder};
use dns_message::{QClass, QType};
use std::hint::black_box;

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

/// DNS message with answer: example.com A IN 93.184.216.34
fn sample_dns_message_with_answer() -> Vec<u8> {
    vec![
        0x00, 0x01, // ID
        0x81, 0x80, // Flags: QR=1, RD=1, RA=1
        0x00, 0x01, // QDCOUNT=1
        0x00, 0x01, // ANCOUNT=1
        0x00, 0x00, // NSCOUNT=0
        0x00, 0x00, // ARCOUNT=0
        // QNAME: example.com
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        // QTYPE=A, QCLASS=IN
        0x00, 0x01, 0x00, 0x01,
        // ANCOUNT=1, NAME=example.com
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        // TYPE=A, CLASS=IN, TTL=3600
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
        // RDLENGTH=4, RDATA=93.184.216.34
        0x00, 0x04, 0x5d, 0xb8, 0xd8, 0x22,
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

fn bench_message_builder_build(c: &mut Criterion) {
    c.bench_function("message_builder_build", |b| {
        b.iter(|| {
            let mut buffer = Vec::new();
            let _msg = MessageBuilder::query(1)
                .question("example.com", QType::A, QClass::IN)
                .build(black_box(&mut buffer))
                .unwrap();
            black_box(&buffer);
        })
    });
}

fn bench_message_builder_build_encode_direct(c: &mut Criterion) {
    c.bench_function("message_builder_build_encode_direct", |b| {
        b.iter(|| {
            let bytes = MessageBuilder::query(1)
                .question("example.com", QType::A, QClass::IN)
                .build_encode_direct()
                .unwrap();
            black_box(bytes);
        })
    });
}

fn bench_message_ref_builder_build_to(c: &mut Criterion) {
    let data = sample_dns_message();
    let msg_ref = decode_message_ref(&data).unwrap();
    let header = msg_ref.header.decode_header(&data).unwrap();

    c.bench_function("message_ref_builder_build_to", |b| {
        b.iter(|| {
            let mut dst = Vec::new();
            MessageRefBuilder::from_ref(black_box(&msg_ref))
                .id(1)
                .question(black_box(msg_ref.question.questions[0]))
                .build_to(
                    black_box(&mut dst),
                    black_box(&data),
                    black_box(header.id),
                    black_box(header.flags),
                )
                .unwrap();
            black_box(&dst);
        })
    });
}

fn bench_message_builder_with_answer(c: &mut Criterion) {
    c.bench_function("message_builder_with_answer", |b| {
        b.iter(|| {
            let mut buffer = Vec::new();
            let _msg = MessageBuilder::response(1)
                .question("example.com", QType::A, QClass::IN)
                .answer(
                    "example.com",
                    dns_message::resource_record::RRType::A,
                    dns_message::resource_record::RRClass::IN,
                    3600,
                    [93u8, 184, 216, 34],
                )
                .build(black_box(&mut buffer))
                .unwrap();
            black_box(&buffer);
        })
    });
}

fn bench_message_ref_builder_with_answer(c: &mut Criterion) {
    let data = sample_dns_message_with_answer();
    let msg_ref = decode_message_ref(&data).unwrap();
    let header = msg_ref.header.decode_header(&data).unwrap();

    c.bench_function("message_ref_builder_with_answer", |b| {
        b.iter(|| {
            let mut dst = Vec::new();
            MessageRefBuilder::from_ref(black_box(&msg_ref))
                .id(header.id)
                .flags(black_box(header.flags))
                .question(black_box(msg_ref.question.questions[0]))
                .answer(black_box(msg_ref.answer.records[0]))
                .build_to(
                    black_box(&mut dst),
                    black_box(&data),
                    black_box(header.id),
                    black_box(header.flags),
                )
                .unwrap();
            black_box(&dst);
        })
    });
}

fn bench_message_ref_builder_buffer_size(c: &mut Criterion) {
    let data = sample_dns_message();
    let msg_ref = decode_message_ref(&data).unwrap();

    c.bench_function("message_ref_builder_buffer_size", |b| {
        b.iter(|| {
            let size = MessageRefBuilder::from_ref(black_box(&msg_ref))
                .question(black_box(msg_ref.question.questions[0]))
                .buffer_size();
            black_box(size);
        })
    });
}

fn bench_message_ref_builder_write_to_slice(c: &mut Criterion) {
    let data = sample_dns_message();
    let msg_ref = decode_message_ref(&data).unwrap();
    let header = msg_ref.header.decode_header(&data).unwrap();
    let size = 29;

    c.bench_function("message_ref_builder_write_to_slice", |b| {
        b.iter(|| {
            let mut buf = vec![0u8; size];
            let _written = MessageRefBuilder::from_ref(black_box(&msg_ref))
                .id(1)
                .question(black_box(msg_ref.question.questions[0]))
                .write_to_slice(
                    black_box(&mut buf),
                    black_box(&data),
                    black_box(header.id),
                    black_box(header.flags),
                )
                .unwrap();
            black_box(&buf);
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(100);
    targets = bench_decode_message_ref, bench_decode_message, bench_decode_message_via_ref,
        bench_message_builder_build, bench_message_builder_build_encode_direct,
        bench_message_ref_builder_build_to, bench_message_builder_with_answer,
        bench_message_ref_builder_with_answer, bench_message_ref_builder_buffer_size,
        bench_message_ref_builder_write_to_slice
}
criterion_main!(benches);
