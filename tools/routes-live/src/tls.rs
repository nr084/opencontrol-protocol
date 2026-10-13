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
