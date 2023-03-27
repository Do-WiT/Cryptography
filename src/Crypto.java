import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class Crypto {
    public SecretKey generateKey(int keySize) throws NoSuchAlgorithmException {
        if (keySize != KeySpace.BIT256 && keySize != KeySpace.BIT192 && keySize != KeySpace.BIT128) {
            throw new IllegalArgumentException("Invalid key size!");
        }
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keySize);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }
    public IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
    public String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }
    public String decrypt(String algorithm, String cipherText, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }
    public void encryptFile(String algorithm, SecretKey key, IvParameterSpec iv, String filePath)
            throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, IOException {

        File file = new File(filePath);
        MultiFile multiFile = new MultiFile(file.getName(), Files.readAllBytes(file.toPath()));
        byte[] multiFileBytes = serialize(multiFile);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(multiFileBytes);
        FileOutputStream outputStream = new FileOutputStream(file.getParent() + "\\"+ "file.encrypted");
        outputStream.write(cipherText);
        outputStream.close();
    }
    public void decryptFile(String algorithm, SecretKey key, IvParameterSpec iv, String filePath)
            throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {

        File file = new File(filePath);
        byte[] multiFileBytes = Files.readAllBytes(file.toPath());
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(multiFileBytes);
        MultiFile multiFile = (MultiFile) deserialize(cipherText);
        FileOutputStream outputStream = new FileOutputStream(file.getParent() + "\\"+ multiFile.getFileName());
        outputStream.write(multiFile.getContent());
        outputStream.close();
    }
    private byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(out);
        os.writeObject(obj);
        return out.toByteArray();
    }
    private Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        ObjectInputStream is = new ObjectInputStream(in);
        return is.readObject();
    }
    //    public void encryptFile(String algorithm, SecretKey key, IvParameterSpec iv, File inputFile, File outputFile)
//            throws NoSuchPaddingException,
//            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
//            BadPaddingException, IllegalBlockSizeException, IOException {
//
//        Cipher cipher = Cipher.getInstance(algorithm);
//        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
//        FileInputStream inputStream = new FileInputStream(inputFile);
//        FileOutputStream outputStream = new FileOutputStream(outputFile);
//        byte[] buffer = new byte[64];
//        int bytesRead;
//        while ((bytesRead = inputStream.read(buffer)) != -1) {
//            byte[] output = cipher.update(buffer, 0, bytesRead);
//            if (output != null) {
//                outputStream.write(output);
//            }
//        }
//        byte[] outputBytes = cipher.doFinal();
//        if (outputBytes != null) {
//            outputStream.write(outputBytes);
//        }
//        inputStream.close();
//        outputStream.close();
//    }
    //    public void decryptFile(String algorithm, SecretKey key, IvParameterSpec iv, File inputFile, File outputFile)
//            throws IOException, NoSuchPaddingException,
//            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
//            BadPaddingException, IllegalBlockSizeException {
//
//        Cipher cipher = Cipher.getInstance(algorithm);
//        cipher.init(Cipher.DECRYPT_MODE, key, iv);
//        FileInputStream inputStream = new FileInputStream(inputFile);
//        FileOutputStream outputStream = new FileOutputStream(outputFile);
//        byte[] buffer = new byte[64];
//        int bytesRead;
//        while ((bytesRead = inputStream.read(buffer)) != -1) {
//            byte[] output = cipher.update(buffer, 0, bytesRead);
//            if (output != null) {
//                outputStream.write(output);
//            }
//        }
//        byte[] outputBytes = cipher.doFinal();
//        if (outputBytes != null) {
//            outputStream.write(outputBytes);
//        }
//        inputStream.close();
//        outputStream.close();
//    }

}
