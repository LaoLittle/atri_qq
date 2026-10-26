use std::sync::LazyLock;

pub(crate) fn client_builder() -> reqwest::ClientBuilder {
    static TLS_CONFIG: LazyLock<rustls::ClientConfig> = LazyLock::new(|| {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .expect("AWS-LC supports the default TLS protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config
    });
    reqwest::Client::builder().use_preconfigured_tls(TLS_CONFIG.clone())
}
