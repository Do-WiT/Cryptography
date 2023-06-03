package elgamal;

import utils.Utilities;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        Elgamal3 elgamal = new Elgamal3();
//        {
//            KeyPair keyPair = elgamal.generateKeyPair(KeySpace.BIT256 + 16);
//            PublicKey publicKey = keyPair.getPublicKey();
//            PrivateKey privateKey = keyPair.getPrivateKey();
//            System.out.println("==== Public key ====");
//            System.out.println("P : " + publicKey.getP());
//            System.out.println("Q : " + publicKey.getQ());
//            System.out.println("Y : " + publicKey.getY());
//            System.out.println("==== Private key ====");
//            System.out.println("U : " + privateKey.getU());
//
//            KeyPair keyPair2 = elgamal.generateKeyPair(KeySpace.BIT256 + 16);
//            PublicKey publicKey2 = keyPair2.getPublicKey();
//            PrivateKey privateKey2 = keyPair2.getPrivateKey();
//            System.out.println("==== Public key ====");
//            System.out.println("P : " + publicKey2.getP());
//            System.out.println("Q : " + publicKey2.getQ());
//            System.out.println("Y : " + publicKey2.getY());
//            System.out.println("==== Private key ====");
//            System.out.println("U : " + privateKey2.getU());
//
////            String filePath = "C:\\Users\\wit_w\\Desktop\\Test\\Binder1.pdf";
////            String encryptPath = "C:\\Users\\wit_w\\Desktop\\Test\\encrypted-Binder1.encrypted";
////            String filePath = "C:\\Users\\wit_w\\Desktop\\Test\\Open-HEIC-on-Mac.jpg";
////            String encryptPath = "C:\\Users\\wit_w\\Desktop\\Test\\encrypted-Open-HEIC-on-Mac.encrypted";
////            String filePath = "C:\\Users\\wit_w\\Desktop\\Test\\text2.txt";
////            String encryptPath = "C:\\Users\\wit_w\\Desktop\\Test\\encrypted-text2.encrypted";
//            String filePath = "C:\\Users\\wit_w\\Desktop\\Block Chains\\blockchain ai iot.mp4";
//            String encryptPath = "C:\\Users\\wit_w\\Desktop\\Block Chains\\encrypted-blockchain ai iot.encrypted";
//
//            elgamal.encryptFile(filePath, publicKey, publicKey2, privateKey2, MessageDigest.getInstance("sha-256"));
//            elgamal.decryptFile(encryptPath, publicKey2, publicKey, privateKey, MessageDigest.getInstance("sha-256"));
//        }
        Scanner scanner = new Scanner(System.in);
        do {
            System.out.print("Command : " );
            String command = scanner.nextLine();
            try {
                if (command.equalsIgnoreCase("genkey")){
                    System.out.print("Enter Key Size : " );
                    int keySize = Integer.parseInt(scanner.nextLine());
                    System.out.print("Enter Destination Path : ");
                    String path = scanner.nextLine();
                    KeyPair keyPair = elgamal.generateKeyPair(keySize);
                    PublicKey publicKey = keyPair.getPublicKey();
                    PrivateKey privateKey = keyPair.getPrivateKey();
                    System.out.println("==== Public key ====");
                    System.out.println("P : " + publicKey.getP());
                    System.out.println("Q : " + publicKey.getQ());
                    System.out.println("Y : " + publicKey.getY());
                    System.out.println("==== Private key ====");
                    System.out.println("U : " + privateKey.getU());
                    Files.write(Path.of(path + "//public" + Math.abs(publicKey.getP().toByteArray()[1])
                            + "" +  Math.abs(publicKey.getP().toByteArray()[2])
                            + "-" + publicKey.getP().bitLength()+ ".key"), Utilities.serialize(publicKey));
                    Files.write(Path.of(path + "//keyPair" + Math.abs(publicKey.getP().toByteArray()[1])
                            + "" +  Math.abs(publicKey.getP().toByteArray()[2])
                            + "-" + publicKey.getP().bitLength()+ ".key"), Utilities.serialize(keyPair));
                }
                if (command.equalsIgnoreCase("encryptfile")){
                    System.out.print("Enter File Path : ");
                    String path = scanner.nextLine();
                    System.out.print("Enter Receiver Public Key : ");
                    String receiverPublic = scanner.nextLine();
                    System.out.print("Enter  Sender  Key  Pairs : ");
                    String keyPair = scanner.nextLine();
                    System.out.print("Enter  Hash Algo : ");
                    String sign = scanner.nextLine();
                    elgamal.encryptFile(path, receiverPublic, keyPair, sign);

                }
                if (command.equalsIgnoreCase("decryptfile")){
                    System.out.print("Enter File Path : ");
                    String path = scanner.nextLine();
                    System.out.print("Enter   Sender  Public Key : ");
                    String senderPublic = scanner.nextLine();
                    System.out.print("Enter  Receiver Key  Pairs : ");
                    String keyPair = scanner.nextLine();
                    System.out.print("Enter Hash Algo : ");
                    String sign = scanner.nextLine();
                    elgamal.decryptFile(path, senderPublic, keyPair, sign);
                }
            }
            catch (Exception e){
                System.out.println("Catch!!! : " + e.getMessage());
                continue;
            }
        }
        while (true);
    }
}

