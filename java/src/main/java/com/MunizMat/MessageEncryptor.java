package com.MunizMat;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

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
}
