// Copyright 2025 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::sync::Arc;

use crate::protocols::tls::{server::handshake, TlsStream};
use log::debug;
use pingora_error::Result;
use pingora_rustls::load_certs_and_key_files;
use pingora_rustls::ServerConfig;
use pingora_rustls::{version, TlsAcceptor as RusTlsAcceptor};

use crate::protocols::{ALPN, IO};

/// The TLS settings of a listening endpoint
pub struct TlsSettings {
    alpn_protocols: Option<Vec<Vec<u8>>>,
    cert_resolver_strategy: CertResolverStrategy,
}

enum CertResolverStrategy {
    File { cert_path: String, key_path: String },
    Provided(Arc<dyn pingora_rustls::ResolvesServerCert>),
}

pub struct Acceptor {
    pub acceptor: RusTlsAcceptor,
}

impl TlsSettings {
    /// Create a Rustls acceptor based on the current setting for certificates,
    /// keys, and protocols.
    ///
    /// _NOTE_ This function will panic if there is an error in loading
    /// certificate files or constructing the builder
    ///
    /// Todo: Return a result instead of panicking XD
    pub fn build(self) -> Acceptor {
        // TODO - Add support for client auth & custom CA support
        let config =
            ServerConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13])
                .with_no_client_auth();

        let cert_resolver = match self.cert_resolver_strategy {
            CertResolverStrategy::File {
                cert_path,
                key_path,
            } => {
                let Ok(Some((certs, key))) = load_certs_and_key_files(&cert_path, &key_path) else {
                    panic!(
                        "Failed to load provided certificates \"{}\" or key \"{}\".",
                        cert_path, key_path
                    )
                };

                let Ok(certified_key) =
                    pingora_rustls::CertifiedKey::from_der(certs, key, config.crypto_provider())
                else {
                    panic!(
                        "Failed to create certified key with provided certificates \"{}\" and key \"{}\".",
                        cert_path, key_path
                    )
                };

                Arc::new(pingora_rustls::SingleCertAndKey::from(certified_key))
            }
            CertResolverStrategy::Provided(cert_resolver) => cert_resolver,
        };

        let mut config = config.with_cert_resolver(cert_resolver);

        if let Some(alpn_protocols) = self.alpn_protocols {
            config.alpn_protocols = alpn_protocols;
        }

        Acceptor {
            acceptor: RusTlsAcceptor::from(Arc::new(config)),
        }
    }

    /// Enable HTTP/2 support for this endpoint, which is default off.
    /// This effectively sets the ALPN to prefer HTTP/2 with HTTP/1.1 allowed
    pub fn enable_h2(&mut self) {
        self.set_alpn(ALPN::H2H1);
    }

    fn set_alpn(&mut self, alpn: ALPN) {
        self.alpn_protocols = Some(alpn.to_wire_protocols());
    }

    pub fn intermediate(cert_path: &str, key_path: &str) -> Result<Self>
    where
        Self: Sized,
    {
        let cert_resolver_strategy = CertResolverStrategy::File {
            cert_path: cert_path.to_string(),
            key_path: key_path.to_string(),
        };

        Ok(TlsSettings {
            alpn_protocols: None,
            cert_resolver_strategy,
        })
    }

    pub fn with_callbacks(
        cert_resolver: Arc<dyn pingora_rustls::ResolvesServerCert>,
    ) -> Result<Self>
    where
        Self: Sized,
    {
        let cert_resolver_strategy = CertResolverStrategy::Provided(cert_resolver);

        Ok(TlsSettings {
            alpn_protocols: None,
            cert_resolver_strategy,
        })
    }
}

impl Acceptor {
    pub async fn tls_handshake<S: IO>(&self, stream: S) -> Result<TlsStream<S>> {
        debug!("new tls session");
        // TODO: be able to offload this handshake in a thread pool
        handshake(self, stream).await
    }
}
