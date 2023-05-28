package elgamal;

import utils.Utilities;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        Elgamal elgamal = new Elgamal();
        Scanner scanner = new Scanner(System.in);
        do {
            System.out.print("Command : " );
            String command = scanner.nextLine();
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
                Files.write(Path.of(path + "//public" + Math.abs(publicKey.getP().toByteArray()[2])
                                                + "" +  Math.abs(publicKey.getP().toByteArray()[8])
                                                + "-" + publicKey.getP().bitLength()+ ".key"), Utilities.serialize(publicKey));
                Files.write(Path.of(path + "//private" + Math.abs(publicKey.getP().toByteArray()[2])
                                                + "" +  Math.abs(publicKey.getP().toByteArray()[8])
                                                + "-" + publicKey.getP().bitLength()+ ".key"), Utilities.serialize(privateKey));
            }
            if (command.equalsIgnoreCase("encryptfile")){
                System.out.print("Enter File Path : ");
                String path = scanner.nextLine();
                System.out.print("Enter Receiver Public Key : ");
                String receiverPublic = scanner.nextLine();
                System.out.print("Enter  Sender  Public Key : ");
                String senderPublic = scanner.nextLine();
                System.out.print("Enter  Sender Private Key : ");
                String senderPrivate = scanner.nextLine();
                elgamal.encryptFile(path, receiverPublic, senderPublic, senderPrivate);

            }
            if (command.equalsIgnoreCase("decryptfile")){
                System.out.print("Enter File Path : ");
                String path = scanner.nextLine();
                System.out.print("Enter   Sender  Public Key : ");
                String senderPublic = scanner.nextLine();
                System.out.print("Enter  Receiver Public Key : ");
                String receiverPublic = scanner.nextLine();
                System.out.print("Enter Receiver Private Key : ");
                String receiverPrivate = scanner.nextLine();
                elgamal.decryptFile(path, senderPublic, receiverPublic, receiverPrivate);
            }
        }
        while (true);
    }
}

