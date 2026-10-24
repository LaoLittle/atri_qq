fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/signature.proto");
    prost_build::Config::new()
        .protoc_executable(protoc_bin_vendored::protoc_bin_path()?)
        .compile_protos(&["proto/signature.proto"], &["proto"])?;
    Ok(())
}
