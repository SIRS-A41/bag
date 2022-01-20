package com.sirsa41;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

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

    private static PrivateKey stringToPrivateKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] encoded = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
        PrivateKey priv = keyFacPriv.generatePrivate(privSpec);
        return priv;
    }

    private static PublicKey stringToPublicKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] encoded = Base64.getDecoder().decode(key);
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
        PublicKey pub = keyFacPub.generatePublic(pubSpec);
        return pub;
    }

    public static String decrypt(String encryptedText) {
        final String key = Config.getPrivateKey();
        PrivateKey privateKey;
        try {
            privateKey = stringToPrivateKey(key);
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

    public static String encrypt(String plaintext, String key) {
        PublicKey publicKey;
        try {
            publicKey = stringToPublicKey(key);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }

        Cipher encrypt;
        try {
            encrypt = Cipher.getInstance("RSA");
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
            return null;
        } catch (NoSuchPaddingException e1) {
            e1.printStackTrace();
            return null;
        }
        try {
            encrypt.init(Cipher.ENCRYPT_MODE, publicKey);
        } catch (InvalidKeyException e1) {
            e1.printStackTrace();
            return null;
        }

        byte[] encryptedBytes;
        try {
            encryptedBytes = plaintext.getBytes("UTF8");
        } catch (UnsupportedEncodingException e1) {
            e1.printStackTrace();
            return null;
        }
        try {
            final String cipher = new String(Base64.getEncoder().encode(encrypt.doFinal(encryptedBytes)),
                    StandardCharsets.UTF_8);
            return cipher;
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        } catch (BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    static public String deriveKey(String password, String salt, int keyLen)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory kf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec specs = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 2048, keyLen);
        SecretKey key = kf.generateSecret(specs);
        final byte[] encoded = key.getEncoded();
        return Base64.getEncoder().encodeToString(encoded);
    }
}
