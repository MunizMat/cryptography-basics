package com.MunizMat;

public class Helpers {
    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();

        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);

            if(hex.length() == 1) result.append('0');

            result.append(hex);
        }

        return result.toString();
    }
}
