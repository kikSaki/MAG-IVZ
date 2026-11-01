package isp.integrity;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

import fri.isp.Agent;
import fri.isp.Environment;

/**
 * TASK: Alice and Bob share a secret key. Authenticate their messages using
 * HmacSHA256. Complete ten request-reply rounds: Alice sends a message and Bob
 * sends a reply in each round (twenty authenticated messages in total). Both
 * agents must verify the received tag before displaying or using the message.
 * Reject an invalid tag; do not process the corresponding message.
 *
 * Send each message and its tag in the same agreed order. Use a separate Mac
 * instance for each agent and MessageDigest.isEqual to compare tags. For this
 * exercise, the shared key is generated here; do not send it over the channel.
 * HMAC does not encrypt messages or by itself prevent replay attacks.
 * <p>
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Mac.html
 */
public class A1AgentCommunicationHMAC {

    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // TODO: Send ten UTF-8 messages with their tags. Receive and
                // verify Bob's reply in each round before displaying it.

                final String messageA = "What is our opinion on JAVA?";
                final byte[] messageABytes = messageA.getBytes(StandardCharsets.UTF_8);

                for (int i = 0; i < 10; i++) {

                    final Mac mAlice = Mac.getInstance("HmacSHA256");
                    mAlice.init(key);
                    final byte[] tag1 = mAlice.doFinal(messageABytes);

                    //final String messageHmacAsString = Agent.hex(tag1);
                    //System.out.println("HMAC Alice: " + messageHmacAsString);

                    send("bob", tag1);
                    send("bob", messageABytes);


                    final byte[] tagBob = receive("bob");
                    final byte[] messageBobBytes = receive("bob");

                    final Mac mBob = Mac.getInstance("HmacSHA256");
                    mBob.init(key);

                    final byte[] tag2Bob = mBob.doFinal(messageBobBytes);

                    boolean valid = MessageDigest.isEqual(tagBob, tag2Bob);

                    //System.out.println(valid);

                    if (valid) {
                        System.out.println("[BOB]: " + new String(messageBobBytes, StandardCharsets.UTF_8));
                    } else {
                        System.out.println("REJECTED ???");
                    }



                }

            }
        });
        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // TODO: Receive and verify each message before displaying it.
                // Send an authenticated reply in each of the ten rounds.
                final String messageB = "We hAtE JAVA.";
                final byte[] messageBBytes = messageB.getBytes(StandardCharsets.UTF_8);



                for (int i = 0; i < 10; i++) {
                    final byte[] tagAlice = receive("alice");
                    final byte[] messageAliceBytes = receive("alice");

                    final Mac mAlice = Mac.getInstance("HmacSHA256");
                    mAlice.init(key);

                    final byte[] tag1Alice = mAlice.doFinal(messageAliceBytes);

                    boolean valid = MessageDigest.isEqual(tagAlice, tag1Alice);

                    //System.out.println(valid);

                    if (valid) {
                        System.out.println("[ALICE]: " + new String(messageAliceBytes, StandardCharsets.UTF_8));
                    } else {
                        System.out.println("REJECTED ???");
                    }


                    
                    final Mac mBob = Mac.getInstance("HmacSHA256");

                    mBob.init(key);
                    final byte[] tag2 = mBob.doFinal(messageB.getBytes(StandardCharsets.UTF_8));

                    //final String messageHmacAsString = Agent.hex(tag2);
                    //System.out.println("HMAC Bob: " + messageHmacAsString);

                    send("alice", tag2);
                    send("alice", messageBBytes);
                }



            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
