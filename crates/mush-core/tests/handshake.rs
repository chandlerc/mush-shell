// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Real quinn handshakes over loopback UDP exercising the pinning
//! verifiers: correct pins connect and carry data; every wrong or missing
//! credential fails at the TLS level, never as an accepted connection.

mod common;

use std::sync::Arc;

use common::{DEADLINE, client_endpoint, connected_pair, server_endpoint};
use mush_core::pinning::{self, KeyPin, SessionIdentity};
use quinn::ConnectionError;
use tokio::time::timeout;

fn alpn_of(connection: &quinn::Connection) -> Option<Vec<u8>> {
  connection
    .handshake_data()?
    .downcast::<quinn::crypto::rustls::HandshakeData>()
    .ok()?
    .protocol
}

/// A TLS-level handshake failure: either our side aborted (local
/// transport error) or the peer's abort reached us as a connection
/// close. Anything else -- especially success -- is a pinning bug.
fn assert_tls_failure(result: Result<quinn::Connection, ConnectionError>) {
  match result {
    Ok(_) => panic!("handshake unexpectedly accepted"),
    Err(
      ConnectionError::TransportError(_) | ConnectionError::ConnectionClosed(_),
    ) => {}
    Err(other) => panic!("expected a TLS-level failure, got: {other:?}"),
  }
}

/// How much the client is allowed to see before the refusal arrives.
#[derive(Clone, Copy)]
enum Refusal {
  /// The client's own connect must fail.
  AtConnect,
  /// The client may also establish transiently and then be closed at the
  /// TLS level: TLS 1.3 clients complete their side before the server
  /// evaluates the client certificate, so the server's refusal can arrive
  /// after `connect` returns. An application close or a timeout is not one.
  AtConnectOrOnClose,
}

/// Runs one handshake and asserts both endpoints refuse it.
async fn assert_refused(
  server: &quinn::Endpoint,
  client: &quinn::Endpoint,
  tolerance: Refusal,
) -> anyhow::Result<()> {
  let accept = tokio::spawn({
    let server = server.clone();
    async move {
      let incoming = server.accept().await.expect("no incoming");
      incoming.await
    }
  });
  let client_result =
    timeout(DEADLINE, client.connect(server.local_addr()?, "mush")?).await?;
  match (client_result, tolerance) {
    (Ok(connection), Refusal::AtConnectOrOnClose) => {
      let reason = timeout(DEADLINE, connection.closed()).await?;
      assert!(
        matches!(
          reason,
          ConnectionError::ConnectionClosed(_)
            | ConnectionError::TransportError(_)
        ),
        "expected a TLS-level close from the server, got: {reason:?}"
      );
    }
    (result, _) => assert_tls_failure(result),
  }
  assert_tls_failure(timeout(DEADLINE, accept).await??);
  Ok(())
}

#[tokio::test]
async fn correct_pins_connect_and_data_flows() -> anyhow::Result<()> {
  let pair = connected_pair().await?;
  assert_eq!(alpn_of(&pair.client).as_deref(), Some(pinning::ALPN));
  assert_eq!(alpn_of(&pair.server).as_deref(), Some(pinning::ALPN));

  let (mut send, _recv) = pair.client.open_bi().await?;
  send.write_all(b"ssh ciphertext goes here").await?;
  send.finish()?;
  let (_send, mut recv) = timeout(DEADLINE, pair.server.accept_bi()).await??;
  let received = timeout(DEADLINE, recv.read_to_end(1024)).await??;
  assert_eq!(received, b"ssh ciphertext goes here");
  Ok(())
}

#[tokio::test]
async fn wrong_server_pin_fails() -> anyhow::Result<()> {
  let client_identity = SessionIdentity::generate()?;
  let server_identity = SessionIdentity::generate()?;
  // The client pins a key the server does not hold.
  let bogus_pin = KeyPin::from_bytes([0x42; 32]);
  let server_endpoint =
    server_endpoint(&server_identity, client_identity.pin())?;
  let client_endpoint = client_endpoint(&client_identity, bogus_pin)?;

  // The client aborts inside the handshake, so the server must fail too.
  assert_refused(&server_endpoint, &client_endpoint, Refusal::AtConnect).await
}

#[tokio::test]
async fn wrong_client_pin_is_refused_by_server() -> anyhow::Result<()> {
  let client_identity = SessionIdentity::generate()?;
  let server_identity = SessionIdentity::generate()?;
  // The server pins a key the client does not hold; the client's view
  // of the server is correct.
  let bogus_pin = KeyPin::from_bytes([0x42; 32]);
  let server_endpoint = server_endpoint(&server_identity, bogus_pin)?;
  let client_endpoint =
    client_endpoint(&client_identity, server_identity.pin())?;

  assert_refused(
    &server_endpoint,
    &client_endpoint,
    Refusal::AtConnectOrOnClose,
  )
  .await
}

/// A `ServerCertVerifier` that accepts anything: models a client probing
/// the port without Mush's raw-public-key credential model at all.
#[derive(Debug)]
struct AcceptAnything(rustls::crypto::WebPkiSupportedAlgorithms);

impl rustls::client::danger::ServerCertVerifier for AcceptAnything {
  fn verify_server_cert(
    &self,
    _end_entity: &rustls::pki_types::CertificateDer<'_>,
    _intermediates: &[rustls::pki_types::CertificateDer<'_>],
    _server_name: &rustls::pki_types::ServerName<'_>,
    _ocsp_response: &[u8],
    _now: rustls::pki_types::UnixTime,
  ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
    Ok(rustls::client::danger::ServerCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self,
    _message: &[u8],
    _cert: &rustls::pki_types::CertificateDer<'_>,
    _dss: &rustls::DigitallySignedStruct,
  ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
  {
    Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
  }

  fn verify_tls13_signature(
    &self,
    _message: &[u8],
    _cert: &rustls::pki_types::CertificateDer<'_>,
    _dss: &rustls::DigitallySignedStruct,
  ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
  {
    Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
  }

  fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
    self.0.supported_schemes()
  }
}

/// A `CertifiedKey` presenting `spki_der` as its raw-public-key
/// "certificate" while signing with an unrelated Ed25519 key: the
/// credential of an attacker who learned a pinned public key (pins travel
/// over the bootstrap channel and are not secret) but not its private half.
fn forged_certified_key(
  spki_der: &[u8],
) -> anyhow::Result<Arc<rustls::sign::CertifiedKey>> {
  let pkcs8 = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(
    &aws_lc_rs::rand::SystemRandom::new(),
  )
  .map_err(|_| anyhow::anyhow!("keygen failed"))?;
  let signing_key = rustls::crypto::aws_lc_rs::sign::any_eddsa_type(
    &rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec()),
  )?;
  Ok(Arc::new(rustls::sign::CertifiedKey::new(
    vec![rustls::pki_types::CertificateDer::from(spki_der.to_vec())],
    signing_key,
  )))
}

/// A server-side `ClientCertVerifier` that accepts any raw public key but
/// still verifies handshake signatures. The forged peers below use these
/// accept-any verifiers so their handshakes mirror the real configs'
/// certificate-type negotiation exactly: without client auth on the
/// forged server, the real client aborts on the missing
/// client_certificate_type extension before any signature is checked.
#[derive(Debug)]
struct AnyRawKeyClientVerifier(rustls::crypto::WebPkiSupportedAlgorithms);

impl rustls::server::danger::ClientCertVerifier for AnyRawKeyClientVerifier {
  fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
    &[]
  }

  fn verify_client_cert(
    &self,
    _end_entity: &rustls::pki_types::CertificateDer<'_>,
    _intermediates: &[rustls::pki_types::CertificateDer<'_>],
    _now: rustls::pki_types::UnixTime,
  ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
    Ok(rustls::server::danger::ClientCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self,
    _message: &[u8],
    _cert: &rustls::pki_types::CertificateDer<'_>,
    _dss: &rustls::DigitallySignedStruct,
  ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
  {
    Err(rustls::Error::PeerIncompatible(
      rustls::PeerIncompatible::Tls12NotOffered,
    ))
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &rustls::pki_types::CertificateDer<'_>,
    dss: &rustls::DigitallySignedStruct,
  ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
  {
    rustls::crypto::verify_tls13_signature_with_raw_key(
      message,
      &rustls::pki_types::SubjectPublicKeyInfoDer::from(cert.as_ref()),
      dss,
      &self.0,
    )
  }

  fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
    vec![rustls::SignatureScheme::ED25519]
  }

  fn requires_raw_public_keys(&self) -> bool {
    true
  }
}

/// The pin check alone would accept a replayed public key; only the
/// signature verification the verifiers delegate to rustls proves the
/// peer holds the private key. A server presenting the exact pinned SPKI
/// but signing with a different key must fail the handshake.
#[tokio::test]
async fn server_replaying_pinned_key_without_possession_fails()
-> anyhow::Result<()> {
  let client_identity = SessionIdentity::generate()?;
  let pinned_identity = SessionIdentity::generate()?;
  let forged = forged_certified_key(pinned_identity.spki_der())?;

  let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
  let algorithms = provider.signature_verification_algorithms;
  let mut tls = rustls::ServerConfig::builder_with_provider(provider)
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_client_cert_verifier(Arc::new(AnyRawKeyClientVerifier(algorithms)))
    .with_cert_resolver(Arc::new(
      rustls::server::AlwaysResolvesServerRawPublicKeys::new(forged),
    ));
  tls.alpn_protocols = vec![pinning::ALPN.to_vec()];
  let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
  let server_endpoint = quinn::Endpoint::server(
    quinn::ServerConfig::with_crypto(Arc::new(quic)),
    common::loopback(),
  )?;

  // The real Mush client, pinning the replayed key.
  let client_endpoint =
    client_endpoint(&client_identity, pinned_identity.pin())?;

  assert_refused(&server_endpoint, &client_endpoint, Refusal::AtConnect).await
}

/// A client-side `ServerCertVerifier` that accepts any raw public key
/// but still verifies handshake signatures: everything about the forged
/// client below is valid except possession of the pinned key, so the
/// server's refusal can only come from its signature check.
#[derive(Debug)]
struct AnyRawKeyServerVerifier(rustls::crypto::WebPkiSupportedAlgorithms);

impl rustls::client::danger::ServerCertVerifier for AnyRawKeyServerVerifier {
  fn verify_server_cert(
    &self,
    _end_entity: &rustls::pki_types::CertificateDer<'_>,
    _intermediates: &[rustls::pki_types::CertificateDer<'_>],
    _server_name: &rustls::pki_types::ServerName<'_>,
    _ocsp_response: &[u8],
    _now: rustls::pki_types::UnixTime,
  ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
    Ok(rustls::client::danger::ServerCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self,
    _message: &[u8],
    _cert: &rustls::pki_types::CertificateDer<'_>,
    _dss: &rustls::DigitallySignedStruct,
  ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
  {
    Err(rustls::Error::PeerIncompatible(
      rustls::PeerIncompatible::Tls12NotOffered,
    ))
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &rustls::pki_types::CertificateDer<'_>,
    dss: &rustls::DigitallySignedStruct,
  ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
  {
    rustls::crypto::verify_tls13_signature_with_raw_key(
      message,
      &rustls::pki_types::SubjectPublicKeyInfoDer::from(cert.as_ref()),
      dss,
      &self.0,
    )
  }

  fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
    vec![rustls::SignatureScheme::ED25519]
  }

  fn requires_raw_public_keys(&self) -> bool {
    true
  }
}

/// The mirror of the replayed-server test: a client presenting the exact
/// pinned SPKI but signing with a different key must be refused by the
/// real Mush server.
#[tokio::test]
async fn client_replaying_pinned_key_without_possession_is_refused()
-> anyhow::Result<()> {
  let server_identity = SessionIdentity::generate()?;
  let pinned_identity = SessionIdentity::generate()?;
  let server_endpoint =
    server_endpoint(&server_identity, pinned_identity.pin())?;

  let forged = forged_certified_key(pinned_identity.spki_der())?;
  let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
  let algorithms = provider.signature_verification_algorithms;
  let mut tls = rustls::ClientConfig::builder_with_provider(provider)
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AnyRawKeyServerVerifier(
      algorithms,
    )))
    .with_client_cert_resolver(Arc::new(
      rustls::client::AlwaysResolvesClientRawPublicKeys::new(forged),
    ));
  tls.alpn_protocols = vec![pinning::ALPN.to_vec()];
  let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
  let client_endpoint = quinn::Endpoint::client(common::loopback())?;
  client_endpoint
    .set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));

  // As with a wrong client pin, the refusal is the server's.
  assert_refused(
    &server_endpoint,
    &client_endpoint,
    Refusal::AtConnectOrOnClose,
  )
  .await
}

#[tokio::test]
async fn plain_unpinned_client_is_refused() -> anyhow::Result<()> {
  let client_identity = SessionIdentity::generate()?;
  let server_identity = SessionIdentity::generate()?;
  let server_endpoint =
    server_endpoint(&server_identity, client_identity.pin())?;

  // An ordinary TLS client: no raw-public-key extension, no client
  // certificate, trusts whatever the server presents.
  let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
  let algorithms = provider.signature_verification_algorithms;
  let mut tls = rustls::ClientConfig::builder_with_provider(provider)
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAnything(algorithms)))
    .with_no_client_auth();
  tls.alpn_protocols = vec![pinning::ALPN.to_vec()];
  let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
  let client_endpoint = quinn::Endpoint::client(common::loopback())?;
  client_endpoint
    .set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));

  assert_refused(&server_endpoint, &client_endpoint, Refusal::AtConnect).await
}
