package com.MunizMat;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

public class Hmac {
    public static String createHmac(String input, String key){
        try {

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(), "HmacSHA256"));

            byte[] hashedBytes = mac.doFinal(input.getBytes());

            return Helpers.bytesToHex(hashedBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
