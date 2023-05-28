//
//import org.w3c.dom.ls.LSOutput;
//import utils.Utilities;
//
//import java.io.IOException;
//import java.util.*;
//import java.util.concurrent.ThreadLocalRandom;
//
//public class Main {
//    public static void main(String[] args) throws IOException, ClassNotFoundException {
//        Main main = new Main();
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
//
//
////        for (int i = 2; i < 1000; i++) {
////            if (main.isPrime(i))
////                System.out.println(i);
////        }
//
////        System.out.println(main.gcd(100, 10));
////        System.out.println(main.gcd(10, 100));
//
//
////        System.out.println(main.modInverse(12, 26));
////        System.out.println(main.modInverse(26, 12));
//
//
////        System.out.println(Integer.MAX_VALUE);
////        System.out.println((int) Math.pow(2, 8) * (int) Math.pow(2, 22));
////        System.out.println((int) Math.pow(2, 8) * (int) Math.pow(2, 21));
////        System.out.println((int) Math.pow(2, 8) * (int) Math.pow(2, 20));
////        System.out.println((int) Math.pow(2, 8) * (int) Math.pow(2, 19));
////        System.out.println((int) Math.pow(2, 8) * (int) Math.pow(2, 18));
////        System.out.println((int) Math.pow(2, 8) * (int) Math.pow(2, 17));
//        for (int j = 0; j < 1; j++) {
//            int q = 0;
//            int p = 0;
//            int u = 0;
//            int h = 0;
//
//            for (int i = 0; i < 100; i++) {
////                p = ThreadLocalRandom.current().nextInt((int) Math.pow(2, 10), (int) Math.pow(2, 11) - 1);
////                p = ThreadLocalRandom.current().nextInt((int) Math.pow(2, 4), (int) Math.pow(2, 5) -1);
//                p = 1583;
//                if (main.isPrime(p)) {
//                    System.out.println("p : " + p);
//                    do {
////                        q = ThreadLocalRandom.current().nextInt(3, p - 1);
//                        q = 915;
//                    }
//                    while (!main.isZStar(q, p));
//                    System.out.println("q : " + q);
//                    //            TODO IF Q = 0
//                    break;
//                }
//            }
//            u = ThreadLocalRandom.current().nextInt(3, p - 1);
//            System.out.println("u : " + u);
//            //       TODO h = 0 error
//            h = main.fastExpo(q, u, p);
//            System.out.println("h : " + h);
//            System.out.println();
//            String str = "dasdASdaSDW!24@#5235@#51234567890-=qwertyuiop[]asdfghjkl;'zxcvbnm,./!@#$%^&*()_+QWERTYUIOP{}ASDFGHJKL:ZXCVBNM<>?";
//            System.out.println("===== Encrypted =====");
//            String cipher = main.encrypt(str, h, q, p);
//            System.out.println("===== Decrypted =====");
//            String plain = main.decrypt(cipher, u, p);
//            System.out.println("Plain : " + plain);
//            System.out.println(Objects.equals(str, plain));
//
//            if (!Objects.equals(str, plain))
//                break;
//        }
////        System.out.println(main.gcd(3000, 197));
//        System.out.println(main.verifyIsZStar(915, 1583));
//
//
//    }
//    private String decrypt(String cipher, int u, int p) throws IOException, ClassNotFoundException {
//        ArrayList<Integer> ciphers = (ArrayList<Integer>) Utilities.deserialize(Utilities.deBase64(cipher));
//        System.out.println("List cipher : " + ciphers);
//        byte[] block = new byte[ciphers.size() - 1];
//        for (int i = 0; i < block.length; i++) {
//            int b = ciphers.get(i);
//            int a = ciphers.get(ciphers.size() -1);
//            b = fastExpo(b, 1, p);
//            a = fastExpo(a, u, p);
////            TODO HOW TO FIX A AND P WHEN GCD != 1
//            a = modInverse(a, p);
//            block[i] = (byte) fastExpo(b * a, 1,p);
//        }
//        System.out.println("List bytes : " + Arrays.toString(block));
//        return new String(block);
//    }
//    //    private String decrypt(String cipher, int u, int p) throws IOException, ClassNotFoundException {
////        ArrayList<Integer> ciphers = (ArrayList<Integer>) Utilities.deserialize(Utilities.deBase64(cipher));
////        System.out.println("List cipher : " + ciphers);
////        byte[] block = new byte[ciphers.size() - 1];
////        for (int i = 0; i < block.length; i++) {
////            int b = ciphers.get(i);
////            int a = ciphers.get(ciphers.size() -1);
////            b = fastExpo(b, 1, p);
////            a = fastExpo(a, u, p);
////            a = modInverse(a, p);
////            block[i] = (byte) fastExpo(b * a, 1,p);
////        }
////        System.out.println("List bytes : " + Arrays.toString(block));
////        return new String(block);
////    }
//    public String encrypt(String text, int h, int q, int p) throws IOException {
//        byte[] block = text.getBytes();
//        System.out.println("List bytes : " + Arrays.toString(block));
//        List<Integer> ciphers = new ArrayList<>();
//        int k = genK(p);
//        for (byte b:block) {
//            int cipher = fastExpo(fastExpo(h, k, p) * fastExpo(b, 1, p), 1, p);
//            ciphers.add(cipher);
//        }
////        TODO IF GCD(A^U, P) != 1
//        ciphers.add(fastExpo(q, k, p));
//        System.out.println("List cipher : " + ciphers.toString());
//        System.out.println("Cipher : " + Utilities.enBase64(Utilities.serialize(ciphers)));
//        return Utilities.enBase64(Utilities.serialize(ciphers));
//    }
//    private int genK(int p) {
//        int k = 1;
//        do {
//            k = ThreadLocalRandom.current().nextInt(2, p - 1);
//        }
//        while (gcd(k, p -1) != 1);
//        return k;
//    }
//    public boolean isZStar(int q, int p) {
//        Set<Integer> primeFactors = primeFactor(p - 1);
//        primeFactors.forEach(e -> {
//            System.out.print(e + " ");
//            System.out.println();
//        });
//
//        for (int pi : primeFactors) {
//            System.out.println((p -1) / pi);
//            if (fastExpo(q, (p -1) / pi, p) == 1)
//                return false;
//        }
//        return true;
//    }
//    private Set<Integer> primeFactor(int p) {
//        Set<Integer> primeFactors = new HashSet<>();
//        if (p % 2 == 0) {
//            primeFactors.add(2);
//            do {
//                p /= 2;
//            }
//            while (p % 2 == 0);
//        }
//        for (int i = 3; i <= Math.sqrt(p); i += 2) {
//            if (p % i == 0) {
//                primeFactors.add(i);
//                do {
//                    p /= i;
//                }
//                while (p % i == 0);
//            }
//        }
//        if (p > 2) {
//            primeFactors.add(p);
//        }
//        return primeFactors;
//    }
//    public int fastExpo(int n, int expo, int mod) {
////        TODO IF MOD = 0
//        int res = 1;
//        n = n % mod;
//        if (n == 0)
//            return 0;
//        while (expo > 0) {
//            if ((expo & 1) != 0)
//                res = (res * n) % mod;
//            expo = expo >> 1;
////            TODO N*N OVERFLOW
////            TODO N <= 2^8 * 2^8
//            n = (n * n) % mod;
//        }
//        return res;
//    }
//    //    public boolean isPrime(int p){
//////        TODO IF N EQUALS ZERO
////        if (Math.floorDiv(p, 2) == 0)
////            return false;
////        for (int i = 0; i < 100; i++) {
////            int randomNum = ThreadLocalRandom.current().nextInt(1, p);
////            if (gcd(randomNum, p) != 1)
////                return false;
////        }
////        return true;
////    }
//    private int gcd(int a, int b){
////        TODO IF A OR B EQUALS ZERO
//        int remain = a % b;
//        while (remain != 0) {
//            a = b;
//            b = remain;
//            remain = a % b;
//        }
//        return b;
//    }
//    public boolean isPrime(int p){
////        TODO IF N EQUALS ZERO
//        int sqrt = (int) Math.sqrt(p);
//        for (int i = 0; i < 100; i++) {
//            int randomNum = ThreadLocalRandom.current().nextInt(1,  sqrt + 1);
//            if (gcd(randomNum, p) != 1)
//                return false;
//        }
//        return true;
//    }
//    public int modInverse(int A, int M) {
//        int m0 = M;
//        int y = 0, x = 1;
//        if (M == 1)
//            return 0;
//        while (A > 1) {
////            TODO M EQUALS ZERO
//            int q = A / M;
//            int t = M;
//            M = A % M;
//            A = t;
//            t = y;
//            y = x - q * y;
//            x = t;
//        }
//        if (x < 0)
//            x += m0;
//        return x;
//    }
//    public boolean verifyIsZStar(int n, int mod){
//        HashSet<Integer> hashSet = new HashSet<>();
//        for (int i = 1; i < mod; i++) {
//            int p = fastExpo(n, i, mod);
//            if (hashSet.contains(p)){
//                System.out.println("Duplicate : " + p);
//                hashSet.stream().forEach(a -> System.out.print(a + " "));
//                return false;
//            }
//            else
//                hashSet.add(p);
//        }
//        hashSet.stream().sorted().forEach(e -> {
//            System.out.print(e + " ");
//        });
//        return true;
//    }
//
//
//
//}
//        ElgamalV6 elgamal = new ElgamalV6();
//        KeyPair keyPair = elgamal.generateKeyPair(KeySpace.BIT256 + KeySpace.BIT32);
//
//        PublicKey publicKey = keyPair.getPublicKey();
//        PrivateKey privateKey = keyPair.getPrivateKey();
//        System.out.println("==== Public key ====");
//        System.out.println("P : " + publicKey.getP());
//        System.out.println("Q : " + publicKey.getQ());
//        System.out.println("Y : " + publicKey.getY());
//        System.out.println("==== Private key ====");
//        System.out.println("U : " + privateKey.getU());
//
//        System.out.println("================================ Encrypt ========================================");
//            String filePath = "C:\\Users\\wit_w\\Desktop\\Test\\text.txt";
////            String filePath = "C:\\Users\\wit_w\\Desktop\\Test\\f1.zip";
////            String filePath = "C:\\Users\\wit_w\\Desktop\\Test\\2562-2-Lecture-08-RSAandElgamal.pdf";
////        String filePath = "C:\\Users\\wit_w\\Desktop\\Test\\Open-HEIC-on-Mac.jpg";
//        elgamal.encryptFile(filePath, publicKey, privateKey);
//
//        System.out.println("================================ Decrypt ========================================");
//        String encryptedFilePath = "C:\\Users\\wit_w\\Desktop\\Test\\file.encrypted";
//        elgamal.decryptFile(encryptedFilePath, privateKey, publicKey);
//        ElgamalV6 elgamal = new ElgamalV6();
//        KeyPair keyPair = elgamal.generateKeyPair(KeySpace.BIT256 + KeySpace.BIT16);
//        PublicKey publicKey = keyPair.getPublicKey();
//        PrivateKey privateKey = keyPair.getPrivateKey();
//        System.out.println("==== Public key ====");
//        System.out.println("P : " + publicKey.getP());
//        System.out.println("Q : " + publicKey.getQ());
//        System.out.println("Y : " + publicKey.getY());
//        System.out.println("==== Private key ====");
//        System.out.println("U : " + privateKey.getU());
//
//        KeyPair keyPair2 = elgamal.generateKeyPair(KeySpace.BIT256 + KeySpace.BIT16);
//        PublicKey publicKey2 = keyPair2.getPublicKey();
//        PrivateKey privateKey2= keyPair2.getPrivateKey();
//        System.out.println("==== Public key ====");
//        System.out.println("P : " + publicKey2.getP());
//        System.out.println("Q : " + publicKey2.getQ());
//        System.out.println("Y : " + publicKey2.getY());
//        System.out.println("==== Private key ====");
//        System.out.println("U : " + privateKey2.getU());

//        System.out.println("================================ Encrypt ========================================");
//        String filePath = "C:\\Users\\wit_w\\Desktop\\Test\\text.txt";
//        String filePath = "C:\\Users\\wit_w\\Desktop\\Test\\f1.zip";
//        String filePath = "C:\\Users\\wit_w\\Desktop\\Test\\2562-2-Lecture-08-RSAandElgamal.pdf";
//        String filePath = "C:\\Users\\wit_w\\Desktop\\Test\\Binder1.pdf";
//        String filePath = "C:\\Users\\wit_w\\Desktop\\Test\\Open-HEIC-on-Mac.jpg";
//        elgamal.encryptFile(filePath, publicKey2, publicKey, privateKey);
//
//        System.out.println("================================ Decrypt ========================================");
//        String encryptedFilePath = "C:\\Users\\wit_w\\Desktop\\Test\\file.encrypted";
//        elgamal.decryptFile(encryptedFilePath, publicKey, publicKey2, privateKey2);
