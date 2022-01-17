package com.sirsa41;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

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

    private static PrivateKey stringToKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] encoded = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
        PrivateKey priv = keyFacPriv.generatePrivate(privSpec);
        return priv;
    }

    public static String decrypt(String encryptedText) {
        final String key = Config.getPrivateKey();
        PrivateKey privateKey;
        try {
            privateKey = stringToKey(key);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }

        Cipher decrypt;
        try {
            decrypt = Cipher.getInstance("RSA");
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
            return null;
        } catch (NoSuchPaddingException e1) {
            e1.printStackTrace();
            return null;
        }
        try {
            decrypt.init(Cipher.PRIVATE_KEY, privateKey);
        } catch (InvalidKeyException e1) {
            e1.printStackTrace();
            return null;
        }

        final byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        try {
            final String decryptedMessage = new String(decrypt.doFinal(encryptedBytes),
                    StandardCharsets.UTF_8);
            return decryptedMessage;
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        } catch (BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        decrypt("VwG0YJQO6QyY6++B4wShPFA+jMSkwHlmFNmbtViqTnYm3crxZ+SFPeSPSNgC1t0Axyqn0PZF2P6pXUMdusWnqfnZOk7UaC6Hwu8nBLc6GIBUDmRGFW5jxUwDKbSmBztJA3iYyJOVOXcR4VyDRykubG/gBgDDbte/XqJUGY6nSTrJHGSgLqpOGKZnx3oftV+ptE5t051w4J3dRhHhIHNZivJnOC+Ri4UbACAbcFmCSYvOMLzcKtUZnamp62mEBW3paAxw0yaYQ+VfG/v6vvlyg+pvSprmwEouZ3CUXxGwUUti5wITNCe1rQTUXSiCmMWXn95x7a38q9WjpVILlDlTcw==");
    }
}
