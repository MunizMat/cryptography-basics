package com.MunizMat;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hasher {
    public static String hash(String input) {
      try {
          byte[] hashedBytes = MessageDigest.getInstance("sha256").digest(input.getBytes());

          return Helpers.bytesToHex(hashedBytes);
      } catch (NoSuchAlgorithmException e) {
          throw new RuntimeException(e);
      }
    }

    public static String hash(String input, String salt) {
        try {
            String inputWithSalt = input + salt;
            byte[] hashedBytes = MessageDigest.getInstance("sha256").digest(inputWithSalt.getBytes());

            return Helpers.bytesToHex(hashedBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
