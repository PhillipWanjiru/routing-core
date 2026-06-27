fn main() {
    // Phase 1: no protobuf codegen.
    // Proto types are hand-written in core/src/proto.rs using plain Rust structs.
    // Phase 5 will replace these with prost-generated types when the full
    // Kafka pipeline is added and a newer Rust toolchain is available.
    println!("cargo:rerun-if-changed=build.rs");
}
