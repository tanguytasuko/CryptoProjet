package org.example;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CertificateValidator {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        try {
            if (args.length < 2) {
                System.out.println("Usage: validate-cert <format> <certfile> OR validate-cert-chain <format> <certfile1> <certfile2> ... <certfileN>");
                System.exit(1);
            }

            String command = args[0];
            String format = args[1];

            if (command.equalsIgnoreCase("validate-cert")) {
                if (args.length != 3) {
                    System.out.println("Usage: validate-cert <format> <certfile>");
                    System.exit(1);
                }
                String certFile = args[2];
                X509Certificate cert = loadCertificate(format, certFile);
                validateSingleCertificate(cert);
            } else if (command.equalsIgnoreCase("validate-cert-chain")) {
                List<X509Certificate> certChain = new ArrayList<>();
                for (int i = 2; i < args.length; i++) {
                    X509Certificate cert = loadCertificate(format, args[i]);
                    certChain.add(cert);
                }
                validateCertChain(certChain);
            } else {
                System.out.println("Invalid command. Use 'validate-cert' or 'validate-cert-chain'.");
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static X509Certificate loadCertificate(String format, String certFilePath) throws Exception {
        InputStream inStream = null;
        try {
            if ("DER".equalsIgnoreCase(format)) {
                inStream = new FileInputStream(certFilePath);
            } else if ("PEM".equalsIgnoreCase(format)) {
                String pem = new String(Files.readAllBytes(Paths.get(certFilePath)));
                String base64Cert = pem.replace("-----BEGIN CERTIFICATE-----", "")
                        .replace("-----END CERTIFICATE-----", "")
                        .replaceAll("\\s", "");
                byte[] decoded = Base64.getDecoder().decode(base64Cert);
                inStream = new java.io.ByteArrayInputStream(decoded);
            } else {
                throw new IllegalArgumentException("Unsupported format: " + format);
            }

            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(inStream);
        } finally {
            if (inStream != null) {
                inStream.close();
            }
        }
    }

    private static void validateSingleCertificate(X509Certificate cert) throws Exception {
        PublicKey key = cert.getPublicKey();
        String algorithm = key.getAlgorithm();

        if ("RSA".equals(algorithm)) {
            verifyRSASignature(cert);
        } else if ("ECDSA".equals(algorithm)) {
            verifyECDSASignature(cert);
        }

        System.out.println("Subject: " + cert.getSubjectX500Principal().getName());
        System.out.println("Issuer: " + cert.getIssuerX500Principal().getName());
        System.out.println("Valid From: " + cert.getNotBefore());
        System.out.println("Valid To: " + cert.getNotAfter());

        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage != null && keyUsage.length > 0) {
            System.out.println("Key Usage: " + java.util.Arrays.toString(keyUsage));
        } else {
            System.out.println("No Key Usage Information.");
        }

        validateBasicConstraints(cert);
    }

    private static void verifyRSASignature(X509Certificate cert) throws Exception {
        String sigAlgName = cert.getSigAlgName();
        Signature sig = Signature.getInstance(sigAlgName);
        sig.initVerify(cert.getPublicKey());
        sig.update(cert.getTBSCertificate());
        boolean result = sig.verify(cert.getSignature());
        System.out.println("Algorithm: " + sigAlgName);
        System.out.println("Verification result: " + result);
        if (!result) {
            throw new Exception("RSA Signature verification failed.");
        }
    }

    private static void verifyECDSASignature(X509Certificate cert) throws Exception {
        Signature ecdsaSig = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSig.initVerify(cert.getPublicKey());
        ecdsaSig.update(cert.getTBSCertificate());
        if (!ecdsaSig.verify(cert.getSignature())) {
            throw new Exception("ECDSA Signature verification failed.");
        }
    }

    private static void validateBasicConstraints(X509Certificate cert) throws Exception {
        if (cert.getBasicConstraints() == -1) {
            throw new Exception("Certificate is not a CA.");
        }
    }

    private static void validateCertChain(List<X509Certificate> certChain) throws Exception {
        for (int i = 0; i < certChain.size() - 1; i++) {
            X509Certificate child = certChain.get(i);
            X509Certificate parent = certChain.get(i + 1);

            try {
                System.out.println("Verifying certificate:");
                System.out.println("Child subject: " + child.getSubjectX500Principal().getName());
                System.out.println("Parent issuer: " + parent.getIssuerX500Principal().getName());
                System.out.println("Child issuer: " + child.getIssuerX500Principal().getName());
                System.out.println("Parent subject: " + parent.getSubjectX500Principal().getName());

                child.verify(parent.getPublicKey());
                if (!child.getIssuerX500Principal().equals(parent.getSubjectX500Principal())) {
                    throw new Exception("Certificate issuer/subject mismatch");
                }

                validateBasicConstraints(parent);
            } catch (SignatureException e) {
                System.err.println("Error verifying certificate: " + child.getSubjectX500Principal().getName());
                throw e;
            }
        }
        System.out.println("All certificates in the chain are valid.");
    }
}
