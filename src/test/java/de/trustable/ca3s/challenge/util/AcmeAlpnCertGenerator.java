package de.trustable.ca3s.challenge.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;

public class AcmeAlpnCertGenerator {

    // OID for ACME extension (RFC 8737)
    private static final ASN1ObjectIdentifier ACME_OID =
            new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.31");

    public static X509Certificate createAlpnCerticate(final String domain, byte[] challengeBytes) throws NoSuchAlgorithmException, CertIOException, OperatorCreationException, CertificateException {

        // 🔑 1. Generate key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();
/*
        // 🧮 2. Compute keyAuthorization digest
        String keyAuthorization = "token.thumbprint"; // MUST be real in practice
        byte[] sha256 = MessageDigest.getInstance("SHA-256")
                .digest(keyAuthorization.getBytes());
*/

        // Wrap in ASN.1 OCTET STRING
        DEROctetString acmeExtensionValue = new DEROctetString(challengeBytes);

        // 📅 3. Validity (very short-lived)
        Instant now = Instant.now();
        Date notBefore = Date.from(now.minusSeconds(60));
        Date notAfter = Date.from(now.plusSeconds(600)); // ~10 minutes

        // 🧾 4. Subject/Issuer (self-signed)
        X500Name subject = new X500Name("CN=" + domain);

        // 🔨 5. Build certificate
        JcaX509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(
                        subject,
                        BigInteger.valueOf(System.currentTimeMillis()),
                        notBefore,
                        notAfter,
                        subject,
                        keyPair.getPublic()
                );

        // ✅ Subject Alternative Name
        GeneralName san = new GeneralName(GeneralName.dNSName, domain);
        certBuilder.addExtension(
                Extension.subjectAlternativeName,
                false,
                new GeneralNames(san)
        );

        // 🔐 Key Usage
        certBuilder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.digitalSignature)
        );

        // 🌐 Extended Key Usage
        certBuilder.addExtension(
                Extension.extendedKeyUsage,
                false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth)
        );

        // ⭐ ACME extension (CRITICAL)
        certBuilder.addExtension(
                ACME_OID,
                true,
                acmeExtensionValue
        );

        // ✍️ 6. Sign certificate
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .build(keyPair.getPrivate());

        X509CertificateHolder holder = certBuilder.build(signer);

        X509Certificate cert = new JcaX509CertificateConverter()
                .getCertificate(holder);

        return cert;
    }
}
