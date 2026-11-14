package isp.signatures;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

import fri.isp.Agent;
import fri.isp.Environment;

/*
 * Assuming Alice and Bob know each other's authentic public key, exchange signed messages
 * using ECDSA. Complete ten request-reply rounds: Alice sends a signed message and Bob
 * sends a signed reply in each round. Each recipient verifies the signature and rejects
 * invalid messages. Signatures provide integrity and evidence of the signer, not secrecy.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) {
        

        try {

            final Environment env = new Environment();

            // Create key pairs
            final String keyAlgorithm = "EC";
            final String signingAlgorithm = "SHA256withECDSA";

            final KeyPair keyAlice = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();
            final KeyPair keyBob = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();


            //System.out.println(KeyPairGenerator.getInstance(keyAlgorithm).getAlgorithm());

        
        


        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // create a message, sign it,
                // and send the message, signature pair to bob
                // receive the message-signature pair, verify the signature
                // repeat 10 times
                for (int i = 0; i < 10; i++) {
                    
                
                final String message = "Why JAVA, just WHY!";
                final Signature signer = Signature.getInstance(signingAlgorithm);

                signer.initSign(keyAlice.getPrivate());
                signer.update(message.getBytes(StandardCharsets.UTF_8));
                final byte[] signature = signer.sign();
                System.out.println("Signature A: " + Agent.hex(signature));

                send("bob", signature);
                send("bob", message.getBytes(StandardCharsets.UTF_8));


                final byte[] receivedSignature = receive("bob");
                final byte[] receivedMessage = receive("bob");

                final Signature verifier = Signature.getInstance(signingAlgorithm);

                verifier.initVerify(keyBob.getPublic());

                verifier.update(receivedMessage);

                if (verifier.verify(receivedSignature))
                    System.out.println("Valid signature.");
                else
                    System.err.println("Invalid signature.");

                }

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

                for (int i = 0; i < 10; i++) {
                    
                
                final byte[] receivedSignature = receive("alice");
                final byte[] receivedMessage = receive("alice");

                final Signature verifier = Signature.getInstance(signingAlgorithm);

                verifier.initVerify(keyAlice.getPublic());

                verifier.update(receivedMessage);

                if (verifier.verify(receivedSignature))
                    System.out.println("Valid signature.");
                else
                    System.err.println("Invalid signature.");


                final String message = "I know right! JaVa SuCkS!";
                final Signature signer = Signature.getInstance(signingAlgorithm);

                signer.initSign(keyBob.getPrivate());
                signer.update(message.getBytes(StandardCharsets.UTF_8));
                final byte[] signature = signer.sign();
                System.out.println("Signature B: " + Agent.hex(signature));

                send("alice", signature);
                send("alice", message.getBytes(StandardCharsets.UTF_8));

                }

            }
        });

        env.connect("alice", "bob");
        env.start();

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Wrong algorithm");

        }
    }
}
