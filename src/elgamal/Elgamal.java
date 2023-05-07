package elgamal;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

public class Elgamal {
    public KeyPair generateKeyPair(int keySize) {
        BigInteger p = genP(keySize);
        BigInteger q = genQ(p);
        BigInteger u = genU(p);
        BigInteger y = fastExpo(q, u, p);
        PublicKey publicKey = new PublicKey(p, q, y);
        PrivateKey privateKey = new PrivateKey(u);
        return new KeyPair(publicKey, privateKey);
    }

    public String encrypt(String plainText, PublicKey publicKey, RandomKey randomKey, PrivateKey privateKey){
        BigInteger m = new BigInteger(plainText.getBytes());
        System.out.println("m : " + m);
        BigInteger a = fastExpo(publicKey.getQ(), randomKey.getRandomKey(), publicKey.getP());
        BigInteger b = (fastExpo(publicKey.getY(), randomKey.getRandomKey(), publicKey.getP()).multiply(m)).mod(publicKey.getP());
        System.out.println("a : " + a);
        System.out.println("b : " + b);

        decrypt(a, b, publicKey, privateKey);

        return "";
    }
    public String decrypt(BigInteger a, BigInteger b, PublicKey publicKey, PrivateKey privateKey){
        a = fastExpo(a, privateKey.getU(), publicKey.getP());
        a = a.modInverse(publicKey.getP());
        System.out.println("mb : " + a.multiply(b).mod(publicKey.getP()));

        return "";
    }

    public RandomKey generateRandomKey(BigInteger p){
        BigInteger k = BigInteger.TWO;
        BigInteger min = BigInteger.TWO;
        BigInteger max = p.subtract(BigInteger.ONE);
        do {
            k = randomBigInt(min, max);
        }
        while (!max.gcd(k).equals(BigInteger.ONE));
        return new RandomKey(k);
    }
    private BigInteger genP(int keySize) {
        BigInteger p = BigInteger.TWO;
        BigInteger min = BigInteger.TWO.pow(keySize -1);
        BigInteger max = BigInteger.TWO.pow(keySize).subtract(BigInteger.ONE);
        do {
            p = randomBigInt(min, max);
        }
        while (!p.isProbablePrime(p.bitLength()));
        return p;
    }
    private BigInteger genQ(BigInteger p) {
        BigInteger max = p.subtract(BigInteger.ONE);
        BigInteger min = BigInteger.TWO;
        BigInteger alpha;
        Set<BigInteger> setExpo = getExpoPrimeFactor(p);
        do {
            alpha = randomBigInt(min, max);
        }
        while (!isGenerator(alpha, setExpo, p));
//        TODO IF ALPHA = NULL
        return alpha;
    }
    private BigInteger genU(BigInteger p) {
        BigInteger min = BigInteger.TWO;
        BigInteger max = p.subtract(BigInteger.ONE);
        return randomBigInt(min, max);
    }
    private boolean isGenerator(BigInteger alpha, Set<BigInteger> pf, BigInteger p) {
        for (BigInteger pi : pf) {
            BigInteger mod = fastExpo(alpha, pi, p);
            if (mod.equals(BigInteger.ONE)) {
                return false;
            }
        }
        return true;
    }
//    private BigInteger fastExpo(BigInteger base, BigInteger expo, BigInteger p) {
//        String binary = expo.toString(2);
//        HashMap<BigInteger, BigInteger> degreeMap = new HashMap<>();
//        int degree = 0;
//        for (int i = binary.length() -1; i > -1; i--) {
//            if (binary.charAt(i) == '1') {
//                degreeMap.put(BigInteger.TWO.pow(degree), null);
//            }
//            degree++;
//        }
//        BigInteger degreeTwo = BigInteger.ONE;
//        if (degreeMap.containsKey(degreeTwo)) {
//            degreeMap.replace(degreeTwo, base);
//        }
//        BigInteger res = base;
//        degree--;
//        do {
//            degreeTwo = degreeTwo.multiply(BigInteger.TWO);
//            base = (base.multiply(base)).mod(p);
//            if (degreeMap.containsKey(degreeTwo)){
//                degreeMap.replace(degreeTwo, base);
//                res = (res.multiply(base)).mod(p);
//            }
//        }
//        while (degree-- != 0);
//        return res;
//    }
    private BigInteger fastExpo(BigInteger base, BigInteger expo, BigInteger p) {
        char[] binary = expo.toString(2).toCharArray();
        BigInteger res = BigInteger.ONE;
        for (int i = binary.length -2; i > -1 ; i--) {
            base = base.multiply(base).mod(p);
            if (binary[i] == '1'){
                res = res.multiply(base).mod(p);
            }
        }
        return res;
    }

    private Set<BigInteger> getExpoPrimeFactor(BigInteger p) {
        BigInteger expo = p.subtract(BigInteger.ONE);
        Set<BigInteger> factorP = primeFactor(expo);
        factorP = factorP.stream().map(expo::divide).collect(Collectors.toSet());
        return factorP;
    }
    private Set<BigInteger> primeFactor(BigInteger n) {
        Set<BigInteger> primeFactors = new HashSet<>();
        if (n.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            primeFactors.add(BigInteger.TWO);
            do {
                n = n.divide(BigInteger.TWO);
            }
            while (n.mod(BigInteger.TWO).equals(BigInteger.ZERO));
        }
        BigInteger sqrt = n.sqrt();
        for (BigInteger i = new BigInteger("3"); i.compareTo(sqrt) < 0; i = i.add(BigInteger.TWO)) {
            if (n.mod(i).equals(BigInteger.ZERO)) {
                primeFactors.add(i);
                do {
                    n = n.divide(i);
                }
                while (n.mod(i).equals(BigInteger.ZERO));
            }
        }
        if (n.compareTo(BigInteger.TWO) > 0) {
            primeFactors.add(n);
        }
        return primeFactors;
    }
    private BigInteger randomBigInt(BigInteger minLimit, BigInteger maxLimit) {
        BigInteger bigInteger = maxLimit.subtract(minLimit);
        Random randNum = new Random();
        int len = maxLimit.bitLength();
        BigInteger res = new BigInteger(len, randNum);
        if (res.compareTo(minLimit) < 0)
            res = res.add(minLimit);
        if (res.compareTo(bigInteger) >= 0)
            res = res.mod(bigInteger).add(minLimit);
        return res;
    }
    
}
