package elgamal;

import utils.Utilities;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        Elgamal4 elgamal = new Elgamal4();
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
                    System.out.print("Enter Sender Key  Pairs : ");
                    String keyPair = scanner.nextLine();
                    System.out.print("Enter Hash Algo : ");
                    String sign = scanner.nextLine();
                    elgamal.encryptFile(path, receiverPublic, keyPair, sign);

                }
                if (command.equalsIgnoreCase("decryptfile")){
                    System.out.print("Enter File Path : ");
                    String path = scanner.nextLine();
                    System.out.print("Enter Receiver Key Pairs : ");
                    String keyPair = scanner.nextLine();
                    elgamal.decryptFile(path, keyPair);
                }
                if (command.equalsIgnoreCase("verifyfile")){
                    System.out.print("Enter File Path : ");
                    String path = scanner.nextLine();
                    System.out.print("Enter Sender  Public Key : ");
                    String senderPublic = scanner.nextLine();
                    System.out.print("Enter Receiver Key  Pairs : ");
                    String keyPair = scanner.nextLine();
                    System.out.print("Enter Hash Algo : ");
                    String hash = scanner.nextLine();
                    elgamal.verifyMessage(path, senderPublic, keyPair, hash);
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

