package isp.secrecy;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.ChaCha20ParameterSpec;

import fri.isp.Agent;
import fri.isp.Environment;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, encrypt their messages
 * using the ChaCha20 stream cipher to provide confidentiality. Perform ten request-reply rounds:
 * Alice sends one encrypted message and Bob sends one encrypted reply in each round
 * (twenty encrypted messages in total). Both agents must decrypt and display received messages.
 * This exercise does not provide message authentication.
 * <p>
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/spec/ChaCha20ParameterSpec.html
 */
public class A3ChaCha20 {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // Both agents can access this shared key from the enclosing method
        final Key key = KeyGenerator.getInstance("ChaCha20").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Repeat for ten request-reply rounds.
                 *
                 * For this exercise, explicitly specify a 12-byte nonce and an initial block
                 * counter using ChaCha20ParameterSpec. Use a fresh nonce for every encryption,
                 * including Bob's replies: nonces must not repeat under the shared key.
                 * Make the nonce and initial counter available to the receiver; neither is secret.
                 */

                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                final int counter = 0;
                final byte[] counterByte = new byte[1];
                counterByte[0] = counter;
                send("bob", counterByte);
                //System.out.println(counterByte[0]);

                for (int i = 0; i < 10; i++) {
                    final Cipher encrypt = Cipher.getInstance("ChaCha20");
                    final byte[] nonce = new byte[12];
                    SecureRandom.getInstanceStrong().nextBytes(nonce);
                    
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, counter));
                    final byte[] cipherText = encrypt.doFinal(pt);

                    send("bob", nonce);
                    
                    send("bob", cipherText);


                    final byte[] nonce1 = receive("bob");
                    //System.out.println("[IV] bob " + Agent.hex(iv1));
                    //print("Got '%s'", new String(receive("alice")));

                    final byte[] cipherText1 = receive("bob");
                    //System.out.println("[CT] bob " + Agent.hex(cipherText1));

                    final Cipher decrypt = Cipher.getInstance("ChaCha20");

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce1, counter) );
                    final byte[] dt = decrypt.doFinal(cipherText1);
                    //System.out.println("[PT] " + Agent.hex(dt));
                    System.out.println("[MESSAGE - ALICE] " + new String(dt, StandardCharsets.UTF_8));

                }
                




            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // TODO: Receive, decrypt and display Alice's message, then encrypt and send
                // a reply with a fresh nonce. Repeat for ten request-reply rounds.
                final String message = "My hate for java will never end";
                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                int counter;
                final byte[] counterByte = receive("alice");
                counter = counterByte[0];

                for (int i = 0; i < 10; i++) {

                    final byte[] nonce1 = receive("alice");
                    //System.out.println("[IV] bob " + Agent.hex(iv1));
                    //print("Got '%s'", new String(receive("alice")));

                    

                    final byte[] cipherText1 = receive("alice");
                    //System.out.println("[CT] bob " + Agent.hex(cipherText1));

                    final Cipher decrypt = Cipher.getInstance("ChaCha20");

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce1, counter) );
                    final byte[] dt = decrypt.doFinal(cipherText1);
                    //System.out.println("[PT] " + Agent.hex(dt));
                    System.out.println("[MESSAGE - BOB] " + new String(dt, StandardCharsets.UTF_8));



                    final Cipher encrypt = Cipher.getInstance("ChaCha20");
                    final byte[] nonce = new byte[12];
                    SecureRandom.getInstanceStrong().nextBytes(nonce);
                    
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, counter));
                    final byte[] cipherText = encrypt.doFinal(pt);


                    send("alice", nonce);
                    send("alice", cipherText);


                    
                }
                
                
            
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
