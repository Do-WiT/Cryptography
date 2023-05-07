package elgamal;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) throws IOException {
//        System.out.println("h = q^u mod p");
//        System.out.println("select p ");
//        System.out.println("    p in [2^(n-1), 2^n -1]");
//        System.out.println("    p is prime");
//        System.out.println("select q ");
//        System.out.println("    q in Zp*");
//        System.out.println("select u ");
//        System.out.println("calculate h");
//        System.out.println("    if h = 0 ");
//        System.out.println("    repeat select p");
//        System.out.println("select k ");
//        System.out.println("    k if gcd(k, p) != 1");
//        System.out.println("    repeat select k");
        Elgamal elgamal = new Elgamal();
        KeyPair keyPair = elgamal.generateKeyPair(56);
        PublicKey publicKey = keyPair.getPublicKey();
        PrivateKey privateKey = keyPair.getPrivateKey();
        RandomKey randomKey = elgamal.generateRandomKey(publicKey.getP());
        System.out.println("==== Public key ====");
        System.out.println("P : " + publicKey.getP());
        System.out.println("Q : " + publicKey.getQ());
        System.out.println("Y : " + publicKey.getY());
        System.out.println("==== Private key ====");
        System.out.println("U : " + privateKey.getU());
        System.out.println("==== Random key ====");
        System.out.println("K : " + randomKey.getRandomKey());

        System.out.println("==== Encrypt ====");
        String str = "ZZZZ" ;
        elgamal.encrypt(str, publicKey, randomKey, privateKey);

//        byte[] s = {-128};
//        System.out.println(new BigInteger(s));
//        byte[] s1 = {0,-128};
//        System.out.println(new BigInteger(s1));
//        byte[] s2 = {1,-128};
//        System.out.println(new BigInteger(s2));
//        byte[] s3 = {0, 1,-128};
//        System.out.println(new BigInteger(s3));
//        System.out.println(Arrays.toString(new BigInteger(s3).toByteArray()));
//        System.out.println(new BigInteger(s3).toString(2));
//
//        byte[] s4 = { -1,-128};
//        System.out.println(new BigInteger(s4));
//        byte[] s5 = {0, -1, -1};
//        System.out.println(new BigInteger(s5));
//        System.out.println(Arrays.toString(new BigInteger(s5).toByteArray()));
//        System.out.println(new BigInteger(s5).toString(2));


//        byte[] s3 = {-128};
//        System.out.println(new BigInteger(s3));
//        byte[] s4 = {0};
//        System.out.println(new BigInteger(s4));
//        byte[] s5 = {-1};
//        System.out.println(new BigInteger(s5));
//        byte[] s3 = {0,0,-127};
//        System.out.println(new BigInteger(s3));
//        byte[] s4 = {0,0,-1};
//        System.out.println(new BigInteger(s4));
//        byte[] s5 = {0,0,-1};
//        System.out.println(new BigInteger(s5));
//        byte[] s6 = {1,0,0};
//        System.out.println(new BigInteger(s6));
//        byte[] s7 = {127,0,0};
//        System.out.println(new BigInteger(s7));
//        byte[] s8 = {-128,0,0};
//        System.out.println(new BigInteger(s8));
//        byte[] s9 = {-1,0,0};
//        System.out.println(new BigInteger(s9));
//        byte[] s10 = {0,-128,-128,-128,-128};
//        System.out.println(new BigInteger(s10));
//        byte[] s11 = {0, -128,-128,-128,-128};
//        System.out.println(new BigInteger(s11));
//        byte[] s12 = {0, 127,127,127,127};
//        System.out.println(new BigInteger(s12));
//        byte[] s13 = {0, -1,-1,-1,-1};
//        System.out.println(new BigInteger(s13));
//        byte[] s14 = {1, 0,0,0,0};
//        System.out.println(new BigInteger(s14));
//        4294967296






//        byte[] file = Files.readAllBytes(Path.of("C:\\Users\\wit_w\\Desktop\\Test\\2562-2-Lecture-08-RSAandElgamal.pdf"));
//        System.out.println(Arrays.toString(file));

//        BigInteger n = BigInteger.ZERO;
//        for (int i = 0; i < 1000; i++) {
//            System.out.println(n);
//            System.out.println(Arrays.toString(n.toByteArray()));
//            n = n.add(BigInteger.ONE);
//
//        }

//        System.out.println(BigInteger.TWO.pow(24));
//        System.out.println(Arrays.toString(BigInteger.TWO.pow(24).toByteArray()));
//        System.out.println(BigInteger.TWO.pow(24).toString(2));
//
//        System.out.println(BigInteger.TWO.pow(31));
//        System.out.println(Arrays.toString(BigInteger.TWO.pow(31).toByteArray()));
//        System.out.println(BigInteger.TWO.pow(31).toString(2));
//
//        System.out.println(BigInteger.TWO.pow(32));
//        System.out.println(Arrays.toString(BigInteger.TWO.pow(32).toByteArray()));
//        System.out.println(BigInteger.TWO.pow(32).toString(2));


    }
}

