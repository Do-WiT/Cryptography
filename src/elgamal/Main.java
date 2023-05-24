package elgamal;

import utils.KeySpace;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) throws Exception {

        for (int i = 0; i < 1; i++) {
            ElgamalV3 elgamalv2 = new ElgamalV3();
            KeyPair keyPair = elgamalv2.generateKeyPair(KeySpace.BIT512);
            PublicKey publicKey = keyPair.getPublicKey();
            PrivateKey privateKey = keyPair.getPrivateKey();
            System.out.println("==== Public key ====");
            System.out.println("P : " + publicKey.getP());
            System.out.println("Q : " + publicKey.getQ());
            System.out.println("Y : " + publicKey.getY());
            System.out.println("==== Private key ====");
            System.out.println("U : " + privateKey.getU());

            System.out.println("================================ Encrypt ========================================");
//            String filePath = "C:\\Users\\wit_w\\Desktop\\Test\\text.txt";
//            String filePath = "C:\\Users\\wit_w\\Desktop\\Test\\f1.zip";
//            String filePath = "C:\\Users\\wit_w\\Desktop\\Test\\2562-2-Lecture-08-RSAandElgamal.pdf";
//            String filePath = "C:\\Users\\wit_w\\Desktop\\Test\\Open-HEIC-on-Mac.jpg";
            String filePath = "C:\\Users\\wit_w\\Desktop\\Test\\Binder1.pdf";
            elgamalv2.encryptFile(filePath, publicKey);

            System.out.println("================================ Decrypt ========================================");
            String encryptedFilePath = "C:\\Users\\wit_w\\Desktop\\Test\\file.encrypted";
            elgamalv2.decryptFile(encryptedFilePath, privateKey, publicKey);
        }

//        testEncryptedBoundary();
//        testPRange();
//        testPositiveBigInt();
//        testMessageDigest();
    }
    public static void testPBoundary(){
        System.out.println("testPBoundary");
        for (int i = 0; i < 100; i++) {
            ElgamalV2 elgamal = new ElgamalV2();;
            BigInteger n = elgamal.generateKeyPair(KeySpace.BIT128).getPublicKey().getP();
            int l = n.toByteArray().length;
            System.out.println(Arrays.toString(n.toByteArray()));
            System.out.println(n);
            System.out.println(l);
            if (elgamal.generateKeyPair(KeySpace.BIT128).getPublicKey().getP().toByteArray().length != KeySpace.BIT128 / 8){
                System.out.println("Invalid boundary!!");
            }
        }
    }

    public static void testEncryptedBoundary(){

        for (int i = 0; i < 1000; i++) {
            ElgamalV2 elgamalV2 = new ElgamalV2();
            KeyPair keyPair = elgamalV2.generateKeyPair(KeySpace.BIT32);
            BigInteger p = keyPair.getPublicKey().getP();
            BigInteger q = keyPair.getPublicKey().getQ();
            BigInteger y = keyPair.getPublicKey().getY();
            BigInteger k = elgamalV2.generateRandomKey(p).getRandomKey();
            BigInteger u = keyPair.getPrivateKey().getU();

            byte[] zero = {0, 0, 0, 0};
            byte[] lower = {0 , -128, -128, -128};
            byte[] negative = {-128, -128, -128, -128};
            //WRONG
            //byte[] bytePositive = {0, -128, -128, -128, -128};
            //RIGHT
            //byte[] bytePositive = { 0, -128, -128, -128};
            //byte[] bytePositive = { 0, 0, 0, 0};
            //byte[] bytePositive = { 0, 127, 127, 127};
            byte[] bytePositive = { -1};
//            System.out.println(new BigInteger(zero));
//            System.out.println(new BigInteger(lower));
//            System.out.println(new BigInteger(negative));
            System.out.println("Input :  " + new BigInteger(bytePositive));


            BigInteger b = elgamalV2.fastExpo(y, k, p).multiply(new BigInteger(bytePositive)).mod(p);
            BigInteger a = elgamalV2.fastExpo(q, k, p);
//            System.out.println("a : " + Arrays.toString(a.toByteArray()));
//            System.out.println("b : " + Arrays.toString(b.toByteArray()));

            a = elgamalV2.fastExpo(a, u, p).modInverse(p);

            BigInteger res = b.multiply(a).mod(p);
            System.out.println("Output : " + res);

            if (!res.equals(new BigInteger(bytePositive))){
                System.out.println("Not equals!!");
                System.out.println("i : " + i);
                System.out.println("P : " + Arrays.toString(p.toByteArray()));
                System.out.println("In :  " + Arrays.toString(bytePositive));
                System.out.println("Out : " + Arrays.toString(res.toByteArray()));

                break;
            }
        }






    }

    public static void testPRange(){
        BigInteger p = new ElgamalV2().generateKeyPair(KeySpace.BIT128).getPublicKey().getP();
        System.out.println(Arrays.toString(p.toByteArray()));
    }

    public static void  testPositiveBigInt(){
        byte[] a = {-127, -128, -126};
        System.out.println(new BigInteger(a));
        System.out.println(new BigInteger(1, a));
        System.out.println(Arrays.toString(new BigInteger(1, a).toByteArray()));

    }

    public static void testMessageDigest() throws NoSuchAlgorithmException, NoSuchProviderException {
//        byte[] str = "1{123,123,123,123,123};qwertyuiop[[asdfghjkll;zxczvxvbcvbvbnvmas".getBytes();
        byte[] str = "12".getBytes();
        byte[] str1 = "34".getBytes();
        byte[] str2 = "1234".getBytes();

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(str2);
        System.out.println(Arrays.toString(messageDigest.digest()));

//        MessageDigest messageDigest2 = MessageDigest.getInstance("MD5");
//        messageDigest2.update(str1);
//        System.out.println(Arrays.toString(messageDigest2.digest()));

        MessageDigest messageDigest3 = MessageDigest.getInstance("SHA-256");
        messageDigest3.update(str);
        messageDigest3.update(str1);
        System.out.println(Arrays.toString(messageDigest3.digest()));




    }



}

