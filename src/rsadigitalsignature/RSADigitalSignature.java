package rsadigitalsignature;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public class RSADigitalSignature {

    public static void main(String[] args) {
        try {
            // 1. Generate an RSA key pair.
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);

            KeyPair keyPair = generator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            System.out.println("RSA Digital Signature Demo");
            System.out.println("RSA key pair generated successfully.");
            System.out.println("Key size: 2048 bits");
            System.out.println("Signature algorithm: SHA256withRSA");

            // 2. Sign the original message.
            String originalMessage = "Transfer $1000 to Mark";

            byte[] signatureBytes = signMessage(originalMessage, privateKey);

            System.out.println("\nOriginal message: " + originalMessage);
            System.out.println("Digital signature (Base64):");
            System.out.println(
                    Base64.getEncoder().encodeToString(signatureBytes)
            );

            // 3. Verify the original message.
            boolean originalValid = verifySignature(
                    originalMessage, signatureBytes, publicKey
            );

            System.out.println("\nTest 1: Original message");
            System.out.println("Signature valid: " + originalValid);

            // 4. Verify a modified message using the same signature.
            String modifiedMessage = "Transfer $1000 to Oscar";

            boolean modifiedValid = verifySignature(
                    modifiedMessage, signatureBytes, publicKey
            );

            System.out.println("\nTest 2: Modified message");
            System.out.println("Modified message: " + modifiedMessage);
            System.out.println("Signature valid: " + modifiedValid);

            // 5. Verify the original message using a different public key.
            KeyPair anotherKeyPair = generator.generateKeyPair();
            PublicKey wrongPublicKey = anotherKeyPair.getPublic();

            boolean wrongKeyValid = verifySignature(
                    originalMessage, signatureBytes, wrongPublicKey
            );

            System.out.println("\nTest 3: Different public key");
            System.out.println("Message: " + originalMessage);
            System.out.println("Signature valid: " + wrongKeyValid);

        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static byte[] signMessage(
            String message, PrivateKey privateKey
    ) throws Exception {

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(message.getBytes(StandardCharsets.UTF_8));

        return signer.sign();
    }

    private static boolean verifySignature(
            String message, byte[] signatureBytes, PublicKey publicKey
    ) throws Exception {

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(message.getBytes(StandardCharsets.UTF_8));

        return verifier.verify(signatureBytes);
    }
}
