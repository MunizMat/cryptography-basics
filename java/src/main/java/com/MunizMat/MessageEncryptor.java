package com.MunizMat;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.PublicKey;

public class MessageEncryptor {
    public static String encrypt(String message, SecretKey secretKey, IvParameterSpec ivSpec) {
       try {
           Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
           cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
           byte[] encryptedBytes = cipher.doFinal(message.getBytes());

           return Helpers.bytesToHex(encryptedBytes);
       } catch (Exception e) {
           throw new RuntimeException(e);
       }
    }

    public static String encryptWithPublicKey(String message, PublicKey publicKey){
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(message.getBytes());

            return Helpers.bytesToHex(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
