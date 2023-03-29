import java.security.KeyPair;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        Scanner in = new Scanner(System.in);
        Crypto crypto = new Crypto();
//        TODO PRINT COMMAND LIST
        System.out.print("Command : ");
        loop : while (in.hasNextLine()){
            String command = in.nextLine().trim().toLowerCase();
            switch (command) {
                case "gentkey": {
                    System.out.print(" - Enter key size(bit) : ");
                    int keySize = Integer.parseInt(in.nextLine().trim());
                    String key = crypto.generateKey(keySize);
                    System.out.println(" - Secret key : " + key);
                    break;
                }
                case "gentiv": {
                    System.out.println(" - IV : " + crypto.generateIv());
                    break;
                }
                case "encrypttext": {
                    System.out.print(" - Enter secret key : ");
                    String secretKey = in.nextLine();
                    System.out.print(" - Enter IV : ");
                    String iv = in.nextLine();
                    System.out.print(" - Enter text : ");
                    String text = in.nextLine();
                    String cipherText = crypto.encrypt(text, secretKey, iv);
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
                    String plainText = crypto.decrypt(text, secretKey, iv);
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
                    crypto.encryptFile(secretKey, iv, path);
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
                    crypto.decryptFile(secretKey, iv, path);
                    System.out.println(" - Decrypted File");
                    break;
                }
                case "gentkeypair": {
                    System.out.print(" - Enter key size(bit) : ");
                    int keySize = Integer.parseInt(in.nextLine().trim());
                    KeyPair keyPair = crypto.generateKeyPair(keySize);
                    System.out.println(" - Public key : " + Utilities.enBase64(keyPair.getPublic().getEncoded()));
                    System.out.println(" - Private key : " + Utilities.enBase64(keyPair.getPrivate().getEncoded()));
                    break ;
                }
                case "publicencrypt": {
                    System.out.print(" - Enter public key : ");
                    String publicKey = in.nextLine();
                    System.out.print(" - Enter text : ");
                    String text = in.nextLine();
                    String cipher = crypto.publicEncrypt(publicKey, text);
                    System.out.println(" - Cipher text : " + cipher);
                    break;
                }
                case "publicdecrypt": {
                    System.out.print(" - Enter private key : ");
                    String privateKey = in.nextLine();
                    System.out.print(" - Enter cipher : ");
                    String cipher = in.nextLine();
                    String text = crypto.publicDecrypt(privateKey, cipher);
                    System.out.println(" - Plain text : " + text);
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