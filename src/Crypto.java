import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;

public class Crypto {
    private final String algorithm = "AES";
    private final String cipherMode = "CBC";
    private final String pad = "PKCS5Padding";

    public String generateKey(int keySize) throws NoSuchAlgorithmException {
        if (keySize != KeySpace.BIT256 && keySize != KeySpace.BIT192 && keySize != KeySpace.BIT128) {
            throw new IllegalArgumentException("Invalid key size!");
        }
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keySize);
        return Utilities.enBase64(keyGenerator.generateKey().getEncoded());
    }
    public String generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        return Utilities.enBase64(ivParameterSpec.getIV());
    }
    public String encrypt(String text, String key, String ivParameterSpec) throws Exception {
        SecretKey secretKey = stringToSecretKey(key);
        IvParameterSpec iv = stringToIvParameter(ivParameterSpec);
        Cipher cipher = Cipher.getInstance(algorithm + "/" + cipherMode + "/" + pad);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] cipherText = cipher.doFinal(text.getBytes());
        return Utilities.enBase64(cipherText);
    }
    public String decrypt(String cipherText, String key, String ivParameterSpec) throws Exception {
        SecretKey secretKey = stringToSecretKey(key);
        IvParameterSpec iv = stringToIvParameter(ivParameterSpec);
        Cipher cipher = Cipher.getInstance(algorithm + "/" + cipherMode + "/" + pad);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] plainText = cipher.doFinal(Utilities.deBase64(cipherText));
        return new String(plainText);
    }
    private IvParameterSpec stringToIvParameter(String ivParameterSpec) {
        byte[] ivBytes = Utilities.deBase64(ivParameterSpec);
        return new IvParameterSpec(ivBytes);
    }
    private SecretKey stringToSecretKey(String key) {
        byte[] keyBytes = Utilities.deBase64(key);
        return new SecretKeySpec(keyBytes, 0, keyBytes.length, algorithm);
    }
    public void encryptFile(String key, String iv, String filePath) throws Exception{
        SecretKey secretKey = stringToSecretKey(key);
        IvParameterSpec ivParameterSpec = stringToIvParameter(iv);
        File file = new File(filePath);
        MultiFile multiFile = new MultiFile(file.getName(), Files.readAllBytes(file.toPath()));
        byte[] multiFileBytes = Utilities.serialize(multiFile);
        Cipher cipher = Cipher.getInstance(algorithm + "/" + cipherMode + "/" + pad);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] cipherText = cipher.doFinal(multiFileBytes);
        FileOutputStream outputStream = new FileOutputStream(file.getParent() + "\\"+ "file.encrypted");
        outputStream.write(cipherText);
        outputStream.close();
    }
    public void decryptFile(String key, String iv, String filePath) throws Exception{
        SecretKey secretKey = stringToSecretKey(key);
        IvParameterSpec ivParameterSpec = stringToIvParameter(iv);
        File file = new File(filePath);
        byte[] multiFileBytes = Files.readAllBytes(file.toPath());
        Cipher cipher = Cipher.getInstance(algorithm + "/" + cipherMode + "/" + pad);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] cipherText = cipher.doFinal(multiFileBytes);
        MultiFile multiFile = (MultiFile) Utilities.deserialize(cipherText);
        FileOutputStream outputStream = new FileOutputStream(file.getParent() + "\\"+ multiFile.getFileName());
        outputStream.write(multiFile.getContent());
        outputStream.close();
    }
    public KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
        if (keySize != KeySpace.BIT2048 && keySize != KeySpace.BIT1024) {
            throw new IllegalArgumentException("Invalid key size!");
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }

    public String publicEncrypt(String publicKey, String message) throws Exception {
        RSAPublicKey pubKey = (RSAPublicKey) stringToPublicKey(publicKey);
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] cipher = encryptCipher.doFinal(message.getBytes());
        return Utilities.enBase64(cipher);
    }
    public String publicDecrypt(String privateKey, String cipher) throws Exception{
        PrivateKey priKey = stringToPrivateKey(privateKey);
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.DECRYPT_MODE, priKey);
        byte[] plain = encryptCipher.doFinal(Utilities.deBase64(cipher));
        return new String(plain);
    }
    private PublicKey stringToPublicKey(String key) throws Exception {
        byte[] publicBytes = Utilities.deBase64(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
    private PrivateKey stringToPrivateKey(String key) throws Exception {
        byte[] privateBytes = Utilities.deBase64(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

}
