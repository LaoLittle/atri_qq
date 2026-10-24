fn main() {
    println!("cargo:rerun-if-changed=proto");
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("build output"));
    let mut schemas: Vec<_> = std::fs::read_dir("proto")
        .expect("protobuf schema directory")
        .map(|entry| entry.expect("protobuf schema entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "proto")
        })
        .collect();
    schemas.sort();
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    config.bytes(["."]);
    config.enable_type_names();
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.include_file("generated.rs");
    config.file_descriptor_set_path(output.join("atri-qq-descriptors.bin"));
    config
        .compile_protos(&schemas, &["proto"])
        .expect("compile QQ protobuf schemas");
}
