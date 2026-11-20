package isp.keyagreement;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;

public class AuthenticatedKeyExchange {
    public static void main(String[] args) throws GeneralSecurityException {
        final KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        final KeyPair rsaKeys = rsa.generateKeyPair();
        final PublicKey serverPublicKey = rsaKeys.getPublic();
        final PrivateKey serverPrivateKey = rsaKeys.getPrivate();
        final byte[] password = "alice-lab-password".getBytes(StandardCharsets.UTF_8);
        final byte[] abort = new byte[0];

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() {
                try {
                    final KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
                    ec.initialize(256);
                    final KeyPair aliceKeys = ec.generateKeyPair();
                    final byte[] a = aliceKeys.getPublic().getEncoded();
                    send("server", a);

                    final byte[] b = receive("server");
                    if (b.length == 0) {
                        print("Handshake aborted by server.");
                        return;
                    }
                    final byte[] signature = receive("server");
                    final byte[] challengeIv = receive("server");
                    final byte[] encryptedChallenge = receive("server");

                    final Signature verifier = Signature.getInstance("SHA256withRSA");
                    verifier.initVerify(serverPublicKey);
                    verifier.update(a);
                    verifier.update(b);
                    if (!verifier.verify(signature)) {
                        send("server", abort);
                        print("Handshake aborted (invalid server signature).");
                        return;
                    }
                    print("Server authenticated.");

                    final PublicKey serverEcKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(b));
                    final KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");
                    ecdh.init(aliceKeys.getPrivate());
                    ecdh.doPhase(serverEcKey, true);

                    final MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                    final byte[] keyHash = sha256.digest(ecdh.generateSecret());
                    final SecretKeySpec aesKey = new SecretKeySpec(keyHash, 0, 16, "AES");

                    final Cipher challengeCipher = Cipher.getInstance("AES/GCM/NoPadding");
                    challengeCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, challengeIv));
                    final byte[] challenge = challengeCipher.doFinal(encryptedChallenge);

                    sha256.update(password);
                    final byte[] response = sha256.digest(challenge);

                    final Cipher responseCipher = Cipher.getInstance("AES/GCM/NoPadding");
                    responseCipher.init(Cipher.ENCRYPT_MODE, aesKey);
                    final byte[] encryptedResponse = responseCipher.doFinal(response);
                    send("server", responseCipher.getIV());
                    send("server", encryptedResponse);
                } catch (GeneralSecurityException e) {
                    send("server", abort);
                    print("Handshake aborted (%s).", e.getMessage());
                }
            }
        });

        env.add(new Agent("server") {
            @Override
            public void task() {
                final byte[] a = receive("alice");
                if (a.length == 0) {
                    print("Handshake aborted by Alice.");
                    return;
                }

                final byte[] challenge = new byte[32];
                final SecretKeySpec aesKey;
                final MessageDigest sha256;
                try {
                    final ECPublicKey aliceEcKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(a));
                    final KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
                    ec.initialize(aliceEcKey.getParams());
                    final KeyPair serverKeys = ec.generateKeyPair();
                    final byte[] b = serverKeys.getPublic().getEncoded();

                    final KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");
                    ecdh.init(serverKeys.getPrivate());
                    ecdh.doPhase(aliceEcKey, true);

                    sha256 = MessageDigest.getInstance("SHA-256");
                    final byte[] keyHash = sha256.digest(ecdh.generateSecret());
                    aesKey = new SecretKeySpec(keyHash, 0, 16, "AES");

                    final Signature signer = Signature.getInstance("SHA256withRSA");
                    signer.initSign(serverPrivateKey);
                    signer.update(a);
                    signer.update(b);
                    final byte[] signature = signer.sign();

                    new SecureRandom().nextBytes(challenge);
                    final Cipher challengeCipher = Cipher.getInstance("AES/GCM/NoPadding");
                    challengeCipher.init(Cipher.ENCRYPT_MODE, aesKey);
                    final byte[] encryptedChallenge = challengeCipher.doFinal(challenge);

                    send("alice", b);
                    send("alice", signature);
                    send("alice", challengeCipher.getIV());
                    send("alice", encryptedChallenge);
                } catch (GeneralSecurityException e) {
                    send("alice", abort);
                    print("Handshake aborted (%s).", e.getMessage());
                    return;
                }

                final byte[] responseIv = receive("alice");
                if (responseIv.length == 0) {
                    print("Handshake aborted by Alice.");
                    return;
                }
                final byte[] encryptedResponse = receive("alice");

                try {
                    final Cipher responseCipher = Cipher.getInstance("AES/GCM/NoPadding");
                    responseCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, responseIv));
                    final byte[] response = responseCipher.doFinal(encryptedResponse);

                    sha256.update(password);
                    final byte[] expectedResponse = sha256.digest(challenge);
                    if (!MessageDigest.isEqual(expectedResponse, response)) {
                        print("Handshake aborted (incorrect password response).");
                        return;
                    }
                    print("Alice authenticated. Handshake complete.");
                } catch (GeneralSecurityException e) {
                    print("Handshake aborted (%s).", e.getMessage());
                }
            }
        });

        env.connect("alice", "server");
        env.start();
    }
}