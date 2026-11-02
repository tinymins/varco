//! TLS 1.3 with a self-signed server key that clients pin by SPKI hash.
use crate::credential::Pin;
use anyhow::{Context, Result};
use rcgen::PublicKeyData;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// SNI is disabled, so this name never leaves the process.
pub const TLS_NAME: &str = "varco";

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

pub struct Identity {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
    pub pin: Pin,
}

fn identity_from(key_pair: &rcgen::KeyPair) -> Result<Identity> {
    let cert = rcgen::CertificateParams::new(vec![TLS_NAME.to_owned()])?.self_signed(key_pair)?;
    Ok(Identity {
        cert: cert.der().clone(),
        key: PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
        pin: Sha256::digest(key_pair.subject_public_key_info()).into(),
    })
}

pub fn generate_identity() -> Result<Identity> {
    identity_from(&rcgen::KeyPair::generate()?)
}

/// Only the key is stored. The certificate is rebuilt on each start, and the
/// pin covers the key alone, so issued credentials stay valid across restarts.
pub fn load_or_create_identity(path: &Path) -> Result<Identity> {
    let key_pair = match std::fs::read_to_string(path) {
        Ok(pem) => rcgen::KeyPair::from_pem(&pem)
            .with_context(|| format!("parsing server key {}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key_pair = rcgen::KeyPair::generate()?;
            write_private(path, &key_pair.serialize_pem())
                .with_context(|| format!("writing server key {}", path.display()))?;
            key_pair
        }
        Err(e) => return Err(e).with_context(|| format!("reading server key {}", path.display())),
    };
    identity_from(&key_pair)
}

fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(contents.as_bytes())
}

pub fn server_config(identity: &Identity) -> Result<Arc<ServerConfig>> {
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![identity.cert.clone()], identity.key.clone_key())?;
    Ok(Arc::new(config))
}

pub fn client_config(pin: Pin) -> Result<Arc<ClientConfig>> {
    let verifier = PinVerifier {
        pin,
        algorithms: provider().signature_verification_algorithms,
    };
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.enable_sni = false;
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct PinVerifier {
    pin: Pin,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let cert = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let actual: [u8; 32] = Sha256::digest(cert.subject_public_key_info().as_ref()).into();
        if bool::from(actual.ct_eq(&self.pin)) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // Only TLS 1.3 is enabled, so reaching this is a bug. Fail closed.
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    // This proves the peer holds the pinned key. Without it the pin would only
    // show that the peer had seen the public certificate.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// True when an I/O error from the handshake means the server key failed the pin.
pub fn is_pin_failure(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<Error>())
        .is_some_and(|e| matches!(e, Error::InvalidCertificate(_)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    async fn handshake(identity: &Identity, pin: Pin) -> std::io::Result<()> {
        let (client, server) = tokio::io::duplex(16 * 1024);
        let acceptor = TlsAcceptor::from(server_config(identity).unwrap());
        let server_task = tokio::spawn(async move {
            if let Ok(mut stream) = acceptor.accept(server).await {
                let _ = stream.write_all(b"ok").await;
                let _ = stream.flush().await;
            }
        });
        let connector = TlsConnector::from(client_config(pin).unwrap());
        let name = ServerName::try_from(TLS_NAME).unwrap();
        let mut stream = connector.connect(name, client).await?;
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        server_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn correct_pin_connects() {
        let identity = generate_identity().unwrap();
        handshake(&identity, identity.pin).await.unwrap();
    }

    #[tokio::test]
    async fn wrong_pin_is_reported_as_a_pin_failure() {
        let identity = generate_identity().unwrap();
        let error = handshake(&identity, [0; 32]).await.unwrap_err();
        assert!(is_pin_failure(&error), "got {error:?}");
    }

    #[derive(Debug)]
    struct FixedResolver(Arc<rustls::sign::CertifiedKey>);

    impl rustls::server::ResolvesServerCert for FixedResolver {
        fn resolve(
            &self,
            _hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    /// An impostor presents the genuine public certificate but signs with its
    /// own key. The pin matches, so only the signature check can stop this.
    /// A resolver is used because `with_single_cert` refuses a mismatched pair
    /// up front, and then the client side would never be exercised.
    #[tokio::test]
    async fn stolen_certificate_without_its_key_is_rejected() {
        let genuine = generate_identity().unwrap();
        let impostor_key = generate_identity().unwrap().key;
        let signer = provider()
            .key_provider
            .load_private_key(impostor_key)
            .unwrap();
        let certified = rustls::sign::CertifiedKey::new(vec![genuine.cert.clone()], signer);
        let config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(FixedResolver(Arc::new(certified))));

        let (client, server) = tokio::io::duplex(16 * 1024);
        let acceptor = TlsAcceptor::from(Arc::new(config));
        tokio::spawn(async move {
            let _ = acceptor.accept(server).await;
        });
        let connector = TlsConnector::from(client_config(genuine.pin).unwrap());
        let result = connector
            .connect(ServerName::try_from(TLS_NAME).unwrap(), client)
            .await;
        let Err(error) = result else {
            panic!("impostor without the private key was accepted");
        };
        let inner = error.get_ref().and_then(|e| e.downcast_ref::<Error>());
        assert!(
            matches!(
                inner,
                Some(Error::InvalidCertificate(CertificateError::BadSignature))
            ),
            "rejected for the wrong reason: {error:?}"
        );
    }

    #[test]
    fn key_file_is_created_once_and_keeps_the_pin_stable() {
        let dir = std::env::temp_dir().join(format!("varco-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key.pem");
        let _ = std::fs::remove_file(&path);
        let first = load_or_create_identity(&path).unwrap();
        let second = load_or_create_identity(&path).unwrap();
        assert_eq!(first.pin, second.pin);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
