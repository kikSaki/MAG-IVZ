package isp.secrecy;

import java.nio.charset.StandardCharsets;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import fri.isp.Agent;
import fri.isp.Environment;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, encrypt their messages
 * using AES in counter mode to provide confidentiality. Perform ten request-reply rounds:
 * Alice sends one encrypted message and Bob sends one encrypted reply in each round
 * (twenty encrypted messages in total). Both agents must decrypt and display received messages.
 * This exercise does not provide message authentication.
 * <p>
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/spec/IvParameterSpec.html
 */
public class A2AESInCTRMode {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // Both agents can access this shared key from the enclosing method
        final Key key = KeyGenerator.getInstance("AES").generateKey();

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
                 * Use a fresh IV for every encryption, including Bob's replies.
                 * Counter blocks must never repeat under this shared key, in either direction;
                 * the counter ranges used by different messages must not overlap.
                 * Send the IV along with the ciphertext; it need not be secret.
                 * A cipher-generated IV can be accessed via cipher.getIV().
                 */

                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                //System.out.println("[PT] " + Agent.hex(pt));

                final Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding");
                
                /* final byte[] nonce = new byte[12];
                SecureRandom.getInstanceStrong().nextBytes(nonce);
                final int counter = 0; */

                for (int i = 0; i < 10; i++) {
                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] cipherText = encrypt.doFinal(pt);
                    final byte[] iv = encrypt.getIV();
                    System.out.println("[IV] " + Agent.hex(iv));
                    System.out.println("[CT] " + Agent.hex(cipherText));

                    send("bob", iv);
                    send("bob", cipherText);

                    final byte[] iv1 = receive("bob");
                    //System.out.println("[IV] bob " + Agent.hex(iv1));
                    //print("Got '%s'", new String(receive("alice")));

                    final byte[] cipherText1 = receive("bob");
                    //System.out.println("[CT] bob " + Agent.hex(cipherText1));

                    final Cipher decrypt = Cipher.getInstance("AES/CTR/NoPadding");

                    IvParameterSpec ivSpec = new IvParameterSpec(iv1);
                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpec);
                    final byte[] dt = decrypt.doFinal(cipherText1);
                    //System.out.println("[PT] " + Agent.hex(dt));
                    System.out.println("[MESSAGE - BOB] " + new String(dt, StandardCharsets.UTF_8));


                }


            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /* TODO STEP 4
                 * Bob receives, decrypts and displays a message.
                 * Wrap the received IV bytes in IvParameterSpec for the init() call:
                 *
                 *   IvParameterSpec ivSpec = new IvParameterSpec(iv);
                 *   aes.init(Cipher.DECRYPT_MODE, key, ivSpec);
                 *
                 * Encrypt and send a reply using a fresh IV in each round.
                 */
                final String message = "If it wasnt't java I'd return the favor. But I won't!";


                for (int i = 0; i < 10; i++) {
                    final byte[] iv = receive("alice");
                    //System.out.println("[IV] bob " + Agent.hex(iv));
                    //print("Got '%s'", new String(receive("alice")));

                    final byte[] cipherText = receive("alice");
                    //System.out.println("[CT] bob " + Agent.hex(cipherText));
                    
                    final Cipher decrypt = Cipher.getInstance("AES/CTR/NoPadding");

                    IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpec);
                    final byte[] dt = decrypt.doFinal(cipherText);
                    //System.out.println("[PT] " + Agent.hex(dt));
                    System.out.println("[MESSAGE ALICE] " + new String(dt, StandardCharsets.UTF_8));


                    final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                    //System.out.println("[PT] " + Agent.hex(pt));

                    final Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding");
                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] cipherText1 = encrypt.doFinal(pt);
                    final byte[] iv1 = encrypt.getIV();
                    System.out.println("[IV - BOB] " + Agent.hex(iv1));
                    System.out.println("[CT - BOB] " + Agent.hex(cipherText1));

                    send("alice", iv1);
                    send("alice", cipherText1);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
