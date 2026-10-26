use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
    CertificateError, ClientConfig, DigitallySignedStruct, Error, SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use x509_parser::prelude::*;

/// Explicit per-profile leaf certificate trust; never TOFU or a permissive verifier.
#[derive(Debug)]
struct PinnedCertificate {
    fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}
impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        certificate: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if certificate.len() > 65536
            || Sha256::digest(certificate.as_ref()).as_slice() != self.fingerprint
        {
            return Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        let (_, parsed) = parse_x509_certificate(certificate.as_ref())
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let timestamp = i64::try_from(now.as_secs())
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if timestamp < parsed.validity().not_before.timestamp() {
            return Err(Error::InvalidCertificate(CertificateError::NotValidYet));
        }
        if timestamp > parsed.validity().not_after.timestamp() {
            return Err(Error::InvalidCertificate(CertificateError::Expired));
        }
        // Explicit leaf trust authenticates this exact certificate, including its public key.
        // TLS CertificateVerify still proves possession; CA/DNS validation is the separate default mode.
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
#[allow(dead_code)] // Shared by separate client and endpoint diagnostic binaries.
pub fn pinned(certificate: &[u8]) -> anyhow::Result<ClientConfig> {
    anyhow::ensure!(
        !certificate.is_empty() && certificate.len() <= 65536,
        "trusted certificate size"
    );
    let fingerprint: [u8; 32] = Sha256::digest(certificate).into();
    let verifier = PinnedCertificate {
        fingerprint,
        provider: Arc::new(rustls::crypto::ring::default_provider()),
    };
    Ok(ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}

#[allow(dead_code)]
pub fn pinned_client(
    certificate: &[u8],
    client: Vec<u8>,
    key: Vec<u8>,
) -> anyhow::Result<ClientConfig> {
    anyhow::ensure!(
        !certificate.is_empty() && certificate.len() <= 65536,
        "trusted certificate size"
    );
    let verifier = PinnedCertificate {
        fingerprint: Sha256::digest(certificate).into(),
        provider: Arc::new(rustls::crypto::ring::default_provider()),
    };
    Ok(ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(
            vec![CertificateDer::from(client)],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
        )?)
}

impl rustls::server::danger::ClientCertVerifier for PinnedCertificate {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        certificate: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, Error> {
        let name = ServerName::try_from("explicit-pin.invalid")
            .map_err(|_| Error::General("pin name".into()))?;
        ServerCertVerifier::verify_server_cert(self, certificate, intermediates, &name, &[], now)?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        ServerCertVerifier::verify_tls12_signature(self, message, certificate, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        ServerCertVerifier::verify_tls13_signature(self, message, certificate, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ServerCertVerifier::supported_verify_schemes(self)
    }
}
#[allow(dead_code)]
pub fn pinned_server(
    certificate: &[u8],
    own: Vec<u8>,
    key: Vec<u8>,
) -> anyhow::Result<rustls::ServerConfig> {
    anyhow::ensure!(
        !certificate.is_empty() && certificate.len() <= 65536,
        "trusted certificate size"
    );
    let verifier = PinnedCertificate {
        fingerprint: Sha256::digest(certificate).into(),
        provider: Arc::new(rustls::crypto::ring::default_provider()),
    };
    Ok(rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(
            vec![CertificateDer::from(own)],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
        )?)
}
