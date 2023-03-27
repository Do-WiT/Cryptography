import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;


public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException, ClassNotFoundException {
        Scanner in = new Scanner(System.in);
        Crypto crypto = new Crypto();
        String algorithm = "AES/CBC/PKCS5Padding";

//        TODO PRINT COMMAND LIST
        System.out.print("Command : ");
        loop : while (in.hasNextLine()){
            String command = in.nextLine().trim().toLowerCase();
            switch (command) {
                case "gentkey":
                    System.out.print(" - Enter key size(bit) : ");
                    int keySize = Integer.parseInt(in.nextLine().trim());
                    SecretKey key = crypto.generateKey(keySize);
                    System.out.println(" - Secret key : " + Base64.getEncoder().encodeToString(key.getEncoded()));
                    break;
                case "gentiv": {
                    IvParameterSpec iv = crypto.generateIv();
                    System.out.println(" - IV : " + Base64.getEncoder().encodeToString(iv.getIV()));
                    break;
                }
                case "encrypttext": {
                    System.out.print(" - Enter secret key : ");
                    String secretKey = in.nextLine();
                    System.out.print(" - Enter IV : ");
                    String iv = in.nextLine();
                    System.out.print(" - Enter text : ");
                    String text = in.nextLine();
                    byte[] keyBytes = Base64.getDecoder().decode(secretKey);
                    byte[] ivBytes = Base64.getDecoder().decode(iv);
                    String cipherText = crypto.encrypt(algorithm, text, new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES"), new IvParameterSpec(ivBytes));
                    System.out.println(" - Cipher text : " + cipherText);
                    break;
                }
                case "decrypttext": {
                    System.out.print(" - Enter secret key : ");
                    String secretKey = in.nextLine();
                    System.out.print(" - Enter IV : ");
                    String iv = in.nextLine();
                    System.out.print(" - Enter cipher text : ");
                    String text = in.nextLine();
                    byte[] keyBytes = Base64.getDecoder().decode(secretKey);
                    byte[] ivBytes = Base64.getDecoder().decode(iv);
                    String plainText = crypto.decrypt(algorithm, text, new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES"), new IvParameterSpec(ivBytes));
                    System.out.println(" - Plain text : " + plainText);

                    break;
                }
                case "encryptfile": {
                    System.out.print(" - Enter secret key : ");
                    String secretKey = in.nextLine();
                    System.out.print(" - Enter IV : ");
                    String iv = in.nextLine();
                    System.out.print(" - Enter file path : ");
                    String path = in.nextLine();
                    byte[] keyBytes = Base64.getDecoder().decode(secretKey);
                    byte[] ivBytes = Base64.getDecoder().decode(iv);
                    crypto.encryptFile(algorithm, new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES"), new IvParameterSpec(ivBytes), path);
                    System.out.println(" - Encrypted File");
                    break;
                }
                case "decryptfile": {
                    System.out.print(" - Enter secret key : ");
                    String secretKey = in.nextLine();
                    System.out.print(" - Enter IV : ");
                    String iv = in.nextLine();
                    System.out.print(" - Enter file path : ");
                    String path = in.nextLine();
                    byte[] keyBytes = Base64.getDecoder().decode(secretKey);
                    byte[] ivBytes = Base64.getDecoder().decode(iv);
                    crypto.decryptFile(algorithm, new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES"), new IvParameterSpec(ivBytes), path);
                    System.out.println(" - Decrypted File");
                    break;
                }
                case "q": {
                    break loop;
                }
                default:
                    System.out.println("Invalid command!!");
                    break;
            }
            System.out.print("Command : ");
        }

    }
}