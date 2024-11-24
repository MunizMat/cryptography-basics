package com.MunizMat;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        String input = "Hello World!";

        /*
        * Hashing Examples:
        * */
        System.out.println("-------------- Hashing Examples: --------------");
        System.out.println("Hello World Hashed: " + Hasher.hash(input));
        System.out.println("Hello World Hashed: " + Hasher.hash(input));
        System.out.println("Hello World Hashed with Salt: " + Hasher.hash(input, "my-salt") + "\n");

        /*
        * HMAC Examples:
        * */
        System.out.println("-------------- HMAC Examples: --------------");
        System.out.println(Hmac.createHmac(input, Keys.HMAC));
        System.out.println(Hmac.createHmac(input, Keys.HMAC));
        System.out.println(Hmac.createHmac(input, "random-key") + "\n");

        /**
         * Symetric Encryption Examples
         */
        System.out.println("-------------- Symetric Encryption Examples: --------------");

        String message = "This message will be encrypted";
        System.out.println("Message: " + message);


        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();

        byte[] iv = new byte[16];
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        String encryptedMessage = MessageEncryptor.encrypt(message, secretKey, ivSpec);
        System.out.println("Encrypted Message: " + encryptedMessage);

        String decryptedMessage = MessageDecryptor.decrypt(encryptedMessage, secretKey, ivSpec);
        System.out.println("Decrypted Message: " + decryptedMessage + "\n");

        /**
         * Asymetric Encryption Examples
         */
        System.out.println("-------------- Asymetric Encryption Examples: --------------");

        String messageToEncrypt = "This message will be encrypted with asymetric encryption";

        System.out.println("Message: " + messageToEncrypt);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        String asymetricEncryptedMessage = MessageEncryptor.encryptWithPublicKey(messageToEncrypt, keyPair.getPublic());
        System.out.println("Encrypted message: " + asymetricEncryptedMessage);

        String asymetricDecryptedMessage = MessageDecryptor.decryptWithPrivateKey(asymetricEncryptedMessage, keyPair.getPrivate());
        System.out.println("Decrypted message: " + asymetricDecryptedMessage + "\n");

        /**
         * Digital Signature Examples
         */
        System.out.println("-------------- Asymetric Encryption Examples: --------------");

        String messageToSign = "This message will be signed";

        System.out.println("Message: " + messageToSign);

        KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("RSA");
        pairGenerator.initialize(2048);

        KeyPair pair = keyPairGenerator.generateKeyPair();

        Signature signer = Signature.getInstance("SHA256withRSA");

        signer.initSign(pair.getPrivate());
        signer.update(messageToSign.getBytes());

        byte[] signature = signer.sign();

        System.out.println("Signature: " + Helpers.bytesToHex(signature));

        Signature verifier = Signature.getInstance("SHA256withRSA");

        verifier.initVerify(pair.getPublic());
        verifier.update(messageToSign.getBytes());

        boolean isValid = verifier.verify(signature);

        System.out.println("Is valid: " + isValid);

        Signature verifier2 = Signature.getInstance("SHA256withRSA");

        verifier2.initVerify(pair.getPublic());
        verifier2.update("Dummy text".getBytes());

        boolean isValid2 = verifier2.verify(signature);

        System.out.println("Is valid 2: " + isValid2);
    }
}