package com.sirsa41;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Encryption {

    public static String[] generateAsymmetricKeys() {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.out.println("Failed to generate asymmetric key pair");
            return null;
        }
        kpg.initialize(2048);
        final KeyPair keys = kpg.generateKeyPair();
        final String publickey = keyToString(keys.getPublic());
        final String privateKey = keyToString(keys.getPrivate());

        final String[] result = { publickey, privateKey };
        return result;
    }

    private static String keyToString(Key key) {
        byte[] encodedPublicKey = key.getEncoded();
        return Base64.getEncoder().encodeToString(encodedPublicKey);
    }
}
