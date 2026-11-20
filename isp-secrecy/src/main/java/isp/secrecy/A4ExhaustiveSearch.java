package isp.secrecy;

import java.nio.charset.StandardCharsets;
import java.security.Key;

import javax.crypto.Cipher;

import javax.crypto.spec.SecretKeySpec;

import java.util.Random;

import fri.isp.Agent;

/**
 * Implement a brute force key search (exhaustive key search) if you know that the
 * message is:
 * "I would like to keep this text confidential Bob. Kind regards, Alice."
 * <p>
 * Assume the message was encrypted with "DES/ECB/PKCS5Padding".
 * Also assume that the key was poorly chosen. In particular, as an attacker,
 * you are certain that all bytes in the key, with the exception of the last three bytes,
 * have been set to 0.
 * <p>
 * A DES key is represented by 8 bytes, but only 56 bits affect encryption; the remaining
 * bits are parity bits. Varying the last three bytes produces 2^24 byte representations
 * but only 2^21 effective keys. Any equivalent key that correctly decrypts the ciphertext
 * is acceptable; it need not match the original key byte for byte.
 * <p>
 * In main(), generate a demonstration key with the stated restriction, encrypt the supplied
 * message with DES/ECB/PKCS5Padding, and call bruteForceKey(). Verify that the returned key
 * decrypts the ciphertext to the complete original message. Use UTF-8 for text conversion.
 * The search must use only its arguments and the stated key restriction, not the original key.
 * DES and ECB are used only for this teaching exercise, not as recommended encryption.
 * <p>
 * To manually specify a key, use {@link javax.crypto.spec.SecretKeySpec}.
 */
public class A4ExhaustiveSearch {
    public static void main(String[] args) throws Exception {
        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);

        // done
        byte[] desKey = new byte[8];

        Random r = new Random();
        r.nextBytes(desKey);

        /* System.out.print("Random bytes = [ ");
        for (int i = 0; i < desKey.length; i++) {
            System.out.printf("%d ", desKey[i]);
        }
        System.out.println("]"); */
        
        for (int i = 0; i < 5; i++) {
            desKey[i] = 0;

        }
        
        System.out.print("Original key = [ ");
        for (int i = 0; i < desKey.length; i++) {
            System.out.printf("%d ", desKey[i]);
        }
        System.out.println("]");

        final Key key = new SecretKeySpec(desKey, "DES");

        //System.out.println("key - " + key);

        final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
        System.out.println("[PT] " + Agent.hex(pt));

        final Cipher encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");

        encrypt.init(Cipher.ENCRYPT_MODE, key);
        final byte[] cipherText = encrypt.doFinal(pt);
        System.out.println("[CT] " + Agent.hex(cipherText));

        bruteForceKey(cipherText, message);


    }

    /**
     * Recover an 8-byte representation of a key that decrypts ct to the known message.
     * Return null if no matching key exists within the restricted search space.
     */
    public static byte[] bruteForceKey(byte[] ct, String message) throws Exception {
        // done
        //final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
        byte[] findDESKey = new byte[8];
        
        for (int i = 0; i < 5; i++) {
            findDESKey[i] = 0;
        }
        //findDESKey[5] = 1;
        //findDESKey[6] = 1;
        //findDESKey[7] = 1;

        for (int i = -128; i < 128; i++) {
            for (int j = -128; j < 128; j++) {
                for (int k = -128; k < 128; k++) {
                    
                    findDESKey[5] = (byte) i;
                    findDESKey[6] = (byte) j;
                    findDESKey[7] = (byte) k;
                    try{
                        final Key key = new SecretKeySpec(findDESKey, "DES");

                        final Cipher decrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
                        decrypt.init(Cipher.DECRYPT_MODE, key);
                        final byte[] dt = decrypt.doFinal(ct);

                        String dMessage = new String(dt, StandardCharsets.UTF_8);

                        if (message.equals(dMessage)) {
                            System.out.println("[Decrypted MESSAGE] " + new String(dt, StandardCharsets.UTF_8));
                            System.out.print("Decrypted key = [ ");
                            for (int l = 0; l < findDESKey.length; l++) {
                                System.out.printf("%d ", findDESKey[l]);
                            }
                            System.out.println("]");
                            return dt;
                        }
                    }
                    catch (Exception e){

                    }
                    


                }
            }
        }

        
       //System.out.println("[PT] " + Agent.hex(dt));

        // Todo: What happens if the key is incorrect? (Try with RC4 or AES in CTR mode)

        // STEP 5: Create a string from a byte array
        //System.out.println("[MESSAGE] " + new String(dt, StandardCharsets.UTF_8));




        return null;
    }
}
