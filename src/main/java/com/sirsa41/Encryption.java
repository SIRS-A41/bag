package com.sirsa41;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Encryption {

    // generate asymmetric key pair
    public static String[] generateAsymmetricKeys() {
        KeyPairGenerator kpg;
        try {
            // RSA 2048 was used
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.out.println("Failed to generate asymmetric key pair");
            return null;
        }
        kpg.initialize(2048);
        final KeyPair keys = kpg.generateKeyPair();

        // parse the generate keys to strings
        final String publickey = keyToString(keys.getPublic());
        final String privateKey = keyToString(keys.getPrivate());

        final String[] result = { publickey, privateKey };
        return result;
    }

    public static String generateProjectKey() throws NoSuchAlgorithmException {
        // use AES 256
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey key = keyGenerator.generateKey();
        byte[] encodedKey = key.getEncoded();
        // save key using base 64
        return Base64.getEncoder().encodeToString(encodedKey);
    }

    // parse Key to base 64 encoded string
    private static String keyToString(Key key) {
        byte[] encodedPublicKey = key.getEncoded();
        return Base64.getEncoder().encodeToString(encodedPublicKey);
    }

    // load private key from base64 string
    private static PrivateKey stringToPrivateKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] encoded = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
        PrivateKey priv = keyFacPriv.generatePrivate(privSpec);
        return priv;
    }

    // load public key from base64 string
    private static PublicKey stringToPublicKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] encoded = Base64.getDecoder().decode(key);
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
        PublicKey pub = keyFacPub.generatePublic(pubSpec);
        return pub;
    }

    // load AES key from base64 string
    private static Key stringToKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] encoded = Base64.getDecoder().decode(key);
        return (new SecretKeySpec(encoded, 0, 16, "AES"));
    }

    // decrypt string using personal private key (stored locally)
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

    // encrypt string using provided public key
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

    // generate secure random iv
    static public String generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        final IvParameterSpec _iv = new IvParameterSpec(iv);
        return Base64.getEncoder().encodeToString(_iv.getIV());
    }

    static private IvParameterSpec loadIv(String iv) {
        byte[] encoded = Base64.getDecoder().decode(iv);
        return new IvParameterSpec(encoded);
    }

    // encrypt file
    static public File encryptFile(String filepath, String key, String iv) {
        IvParameterSpec _iv = loadIv(iv);
        return processFile(Cipher.ENCRYPT_MODE, filepath, key, _iv);
    }

    // decrypt file
    static public File decryptFile(String filepath, String key, String iv) {
        IvParameterSpec _iv = loadIv(iv);
        return processFile(Cipher.DECRYPT_MODE, filepath, key, _iv);
    }

    // encrypt or decrypt file using specified key and iv
    static private File processFile(int ciphermode, String filepath, String key, IvParameterSpec iv) {
        final File inputFile = new File(filepath);
        Key secretKey;
        try {
            secretKey = stringToKey(key);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e1) {
            System.out.println("Failed to load key");
            return null;
        }
        // use AES/CBC/PKCS5Padding
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }
        // load IV and select cipher mode
        try {
            cipher.init(ciphermode, secretKey, iv);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }

        FileInputStream inputStream;
        try {
            inputStream = new FileInputStream(inputFile);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return null;
        }
        // read file bytes
        byte[] inputBytes = new byte[(int) inputFile.length()];
        try {
            inputStream.read(inputBytes);
            inputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        byte[] outputBytes;
        try {
            // encrypt or decrypt loaded bytes
            outputBytes = cipher.doFinal(inputBytes);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
        String newPath;
        if (ciphermode == Cipher.ENCRYPT_MODE) {
            newPath = inputFile.getAbsolutePath() + ".encrypted";
        } else {
            final String originalPath = inputFile.getAbsolutePath();
            if (originalPath.endsWith(".encrypted")) {
                newPath = originalPath.substring(0, originalPath.lastIndexOf('.'));
            } else {
                newPath = originalPath;
            }

        }

        // write output of cipher.doFinal to a new file
        FileOutputStream outputStream;
        try {
            outputStream = new FileOutputStream(newPath);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return null;
        }

        try {
            outputStream.write(outputBytes);
            outputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        return new File(newPath);

    }

    // derive enhanced password using KDF
    static public String deriveKey(String password, String salt, int keyLen)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory kf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec specs = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 2048, keyLen);
        SecretKey key = kf.generateSecret(specs);
        final byte[] encoded = key.getEncoded();
        return Base64.getEncoder().encodeToString(encoded);
    }

    // sign a string - used to sign the hash of files
    // uses private key stored locally
    static public String signHash(String hash, String privateKey) {
        PrivateKey key;
        try {
            key = stringToPrivateKey(privateKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("Failed to load privte key");
            return null;
        }
        Signature sign;
        try {
            sign = Signature.getInstance("SHA256withRSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        // Initialize the signature
        try {
            sign.initSign(key);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }

        final byte[] inputBytes = Base64.getDecoder().decode(hash);
        // Adding data to the signature
        try {
            sign.update(inputBytes);
        } catch (SignatureException e) {
            e.printStackTrace();
            return null;
        }

        // Calculating the signature
        try {
            byte[] signature = sign.sign();
            return Base64.getEncoder().encodeToString(signature);
        } catch (SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    // convert base64 string to hex string
    static public String hashToHex(String hash) {
        byte[] bytes = Base64.getDecoder().decode(hash);
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    // hash bytes using SHA256
    static public String hashBytes(byte[] bytes) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(bytes);
        return Base64.getEncoder().encodeToString(digest.digest());
    }

    // hash file using SHA256
    static public String hashFile(File file) throws IOException, NoSuchAlgorithmException {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream fis = new FileInputStream(file)) {
            int n = 0;
            byte[] buffer = new byte[8192];
            while (n != -1) {
                n = fis.read(buffer);
                if (n > 0) {
                    digest.update(buffer, 0, n);
                }
            }
        }
        return Base64.getEncoder().encodeToString(digest.digest());

    }

    // hash all files inside a project
    // used to obtain the commit version
    static public String hashProject() throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        final ArrayList<String> files = FilesUtils.ls(FilesUtils.cwd());
        int n;
        byte[] buffer;
        // iterate through every project file
        for (String filepath : files) {
            if (Files.isDirectory(Paths.get(filepath))) {
                ArrayList<String> dirFiles = FilesUtils.lsRecursive(filepath);
                for (String dirFilepath : dirFiles) {
                    try (InputStream fis = new FileInputStream(dirFilepath)) {
                        n = 0;
                        buffer = new byte[8192];
                        while (n != -1) {
                            n = fis.read(buffer);
                            if (n > 0) {
                                digest.update(buffer, 0, n);
                            }
                        }
                    }
                }
            } else {
                try (InputStream fis = new FileInputStream(filepath)) {
                    n = 0;
                    buffer = new byte[8192];
                    while (n != -1) {
                        n = fis.read(buffer);
                        if (n > 0) {
                            digest.update(buffer, 0, n);
                        }
                    }
                }
            }
        }
        // obtain the final hash
        return Base64.getEncoder().encodeToString(digest.digest());
    }

    // validate signature
    static public Boolean validateSignatureBytes(byte[] inputBytes, String signature, String publicKey) {
        PublicKey key;
        try {
            key = stringToPublicKey(publicKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("Failed to load public key");
            return null;
        }
        Signature sign;
        try {
            sign = Signature.getInstance("SHA256withRSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        // Initialize the signature
        try {
            sign.initVerify(key);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }

        // Adding data to the signature
        try {
            sign.update(inputBytes);
        } catch (SignatureException e) {
            e.printStackTrace();
            return null;
        }

        // Validate the signature
        try {
            byte[] _signature = Base64.getDecoder().decode(signature);
            return sign.verify(_signature);
        } catch (SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

    // validate the signature
    // the user provides the computed hash, the signature, and the public key of
    // the signer
    static public Boolean validateSignature(String hash, String signature, String publicKey) {
        PublicKey key;
        try {
            key = stringToPublicKey(publicKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("Failed to load public key");
            return null;
        }
        Signature sign;
        try {
            sign = Signature.getInstance("SHA256withRSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        // Initialize the signature
        try {
            sign.initVerify(key);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }

        byte[] inputBytes = Base64.getDecoder().decode(hash);
        // Adding data to the signature
        try {
            sign.update(inputBytes);
        } catch (SignatureException e) {
            e.printStackTrace();
            return null;
        }

        // Validate the signature
        try {
            byte[] _signature = Base64.getDecoder().decode(signature);
            return sign.verify(_signature);
        } catch (SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }
}
