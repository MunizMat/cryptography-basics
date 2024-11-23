package com.MunizMat;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.HexFormat;

public class MessageDecryptor {
    public static String decrypt(String encryptedMessage, SecretKey secretKey, IvParameterSpec ivSpec) {
        try {
            byte[] binaryData = HexFormat.of().parseHex(encryptedMessage);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            byte[] decryptedBytes = cipher.doFinal(binaryData);

            return new String(decryptedBytes, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
