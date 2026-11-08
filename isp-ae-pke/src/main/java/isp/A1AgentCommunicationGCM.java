package isp;

import java.nio.charset.StandardCharsets;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;

import fri.isp.Agent;
import fri.isp.Environment;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, secure the channel using
 * AES in GCM mode. Complete ten request-reply rounds: Alice sends one
 * encrypted message and Bob sends one encrypted reply in each round (twenty
 * encrypted messages in total). Both agents must decrypt and display the
 * messages they receive. Use a fresh IV for every encryption and send it
 * together with the ciphertext; the IV need not be secret.
 * <p>
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/spec/GCMParameterSpec.html
 */
public class A1AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         */
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String text = "I hope you get this message intact and in secret. Kisses, Alice.";
                final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                //send("bob", pt);

                for (int i = 0; i < 10; i++) {
                    final Cipher aliceS = Cipher.getInstance("AES/GCM/NoPadding");
                    aliceS.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = aliceS.doFinal(pt);
                    final byte[] iv = aliceS.getIV();

                    send("bob", iv);
                    send("bob", ct);

                    final byte[] ivBob = receive("bob");
                    final byte[] ctBob = receive("bob");

                    final Cipher aliceR = Cipher.getInstance("AES/GCM/NoPadding");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, ivBob);
                    aliceR.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt2 = aliceR.doFinal(ctBob);

                    System.out.printf("PT:  %s%n", Agent.hex(pt2));
                    System.out.printf("MSG from Bob: %s%n", new String(pt2, StandardCharsets.UTF_8));

                }
                


                

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

                final String text = "No, this is JAVA.";
                final byte[] pt = text.getBytes(StandardCharsets.UTF_8);


                for (int i = 0; i < 10; i++) {
                    final byte[] ivAlice = receive("alice");
                    final byte[] ctAlice = receive("alice");

                    final Cipher bobR = Cipher.getInstance("AES/GCM/NoPadding");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, ivAlice);
                    bobR.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt2 = bobR.doFinal(ctAlice);

                    System.out.printf("PT:  %s%n", Agent.hex(pt2));
                    System.out.printf("MSG from Alice: %s%n", new String(pt2, StandardCharsets.UTF_8));


                    final Cipher bobS = Cipher.getInstance("AES/GCM/NoPadding");
                    bobS.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = bobS.doFinal(pt);
                    final byte[] iv = bobS.getIV();

                    send("alice", iv);
                    send("alice", ct);
                }
                

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
