package com.MunizMat;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException {
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
        System.out.println("Decrypted Message: " + decryptedMessage);
    }
}