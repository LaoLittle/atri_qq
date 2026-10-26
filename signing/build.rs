fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/signature.proto");
    prost_build::Config::new()
        .protoc_executable(protoc_bin_vendored::protoc_bin_path()?)
        .compile_protos(&["proto/signature.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/ios/extra.proto");
    println!("cargo:rerun-if-changed=proto/ios/token.proto");
    prost_build::Config::new()
        .protoc_executable(protoc_bin_vendored::protoc_bin_path()?)
        .bytes([".ios.signing"])
        .type_attribute(
            ".ios.signing",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .compile_protos(
            &["proto/ios/extra.proto", "proto/ios/token.proto"],
            &["proto"],
        )?;
    Ok(())
}
