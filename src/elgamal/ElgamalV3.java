package elgamal;
import utils.MultiFile;
import utils.Utilities;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

public class ElgamalV3 {
    public KeyPair generateKeyPair(int keySize) {
        Set<BigInteger> primeFactors = primeFactor(keySize);
        BigInteger p = genP(primeFactors);
        BigInteger q = genQ(primeFactors, p);
        BigInteger u = genU(p);
        BigInteger y = q.modPow(u, p);
        PublicKey publicKey = new PublicKey(p, q, y);
        PrivateKey privateKey = new PrivateKey(u);
        return new KeyPair(publicKey, privateKey);
    }
    public void encryptFile(String filePath, PublicKey publicKey) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        RandomKey randomKey = generateRandomKey(publicKey.getP());
        Path fileAttribute = Paths.get(filePath);
        MultiFile multiFile = new MultiFile(fileAttribute.getFileName().toString(), Files.readAllBytes(fileAttribute.toAbsolutePath()));
        byte[] fileBytes = Utilities.serialize(multiFile);
        int blockSize = publicKey.getP().toByteArray().length -1;
        int dataSize = blockSize - 1;
        int cipherSize = fileBytes.length / dataSize;
        int padSize = 0;
        if (fileBytes.length % dataSize != 0){
            padSize = blockSize;
        }
        BigInteger multiB = publicKey.getY().modPow(randomKey.getRandomKey(), publicKey.getP());
        BigInteger a = publicKey.getQ().modPow(randomKey.getRandomKey(), publicKey.getP());
        messageDigest.update(a.toByteArray());
        //PADDING + A (No SIGNATURE)
        byte[] cipher = new byte[(blockSize * cipherSize) + padSize + blockSize + blockSize];
        int fileIndex = 0;
        int cipherIndex = 0;
        while (fileIndex < fileBytes.length - dataSize) {
            BigInteger data = new BigInteger(1, Arrays.copyOfRange(fileBytes, fileIndex, fileIndex + dataSize));
            messageDigest.update(data.toByteArray());
            encryptByte(publicKey.getP(), data, multiB, blockSize, cipherIndex, cipher);
            fileIndex+= dataSize;
            cipherIndex += blockSize;
        }
        //ADD PADDING
        if (fileBytes.length % dataSize != 0){
            BigInteger data = new BigInteger(1, Arrays.copyOfRange(fileBytes, fileIndex, fileIndex + (fileBytes.length % dataSize)));
            encryptByte(publicKey.getP(), data, multiB, blockSize, cipherIndex, cipher);
            messageDigest.update(data.toByteArray());
            cipherIndex += blockSize;
        }


        //ADD A
        //TODO ENCRYPTED
//        encryptByte(publicKey.getP(), a, multiB, blockSize, cipherIndex, cipher);
        setByte(blockSize, cipherIndex, cipher, a);
        cipherIndex += blockSize;

        BigInteger mess = new BigInteger(1, Arrays.copyOfRange(messageDigest.digest(), 0 , messageDigest.getDigestLength()));
        encryptByte(publicKey.getP(), mess, multiB, blockSize, cipherIndex, cipher);


        System.out.println("Encrypted : " + Arrays.toString(mess.toByteArray()));
//        setByte(messageDigest.getDigestLength(), cipherIndex, cipher, new BigInteger(1, mess));
        Files.write(Path.of(fileAttribute.getParent() + "\\" +"file.encrypted"), cipher);
    }
    private void encryptByte(BigInteger p, BigInteger data, BigInteger multiB, int blockSize, int cipherIndex, byte[] cipher) {
        BigInteger b = (multiB.multiply(data)).mod(p);
        setByte(blockSize, cipherIndex, cipher, b);
    }
    private void setByte(int blockSize, int cipherIndex, byte[] cipher, BigInteger n) {
        if (n.toByteArray().length > blockSize){
            System.arraycopy(n.toByteArray(), 1, cipher, cipherIndex, blockSize);
        }
        else {
            int startAt = blockSize - n.toByteArray().length;
            System.arraycopy(n.toByteArray(), 0, cipher, cipherIndex + startAt, n.toByteArray().length);
        }
    }
    public void decryptFile(String filePath, PrivateKey privateKey, PublicKey publicKey) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        Path fileAttribute = Paths.get(filePath);
        byte[] cipher = Files.readAllBytes(fileAttribute.toAbsolutePath());
        int blockSize = publicKey.getP().toByteArray().length -1;
        int dataSize = blockSize - 1;
        int messageDigestSize = blockSize;
        int plainSize = (((cipher.length - messageDigestSize) / blockSize) -2) * dataSize;
        BigInteger pad = new BigInteger(1, Arrays.copyOfRange(cipher, cipher.length - (2 * blockSize) - messageDigestSize, cipher.length - blockSize - messageDigestSize));
        BigInteger a = new BigInteger(1, Arrays.copyOfRange(cipher, cipher.length - blockSize - messageDigestSize, cipher.length - messageDigestSize));
        BigInteger mess = new BigInteger(1, Arrays.copyOfRange(cipher, cipher.length - messageDigestSize, cipher.length));
        BigInteger inverse = a.modPow(privateKey.getU(), publicKey.getP()).modInverse(publicKey.getP());
        pad = pad.multiply(inverse).mod(publicKey.getP());
        mess = mess.multiply(inverse).mod(publicKey.getP());
        byte[] plain = new byte[plainSize + pad.toByteArray().length];
        setByte(dataSize, plain.length - dataSize, plain, pad);
        messageDigest.update(a.toByteArray());
        int cipherIndex = 0;
        int plainIndex = 0;
        while (cipherIndex + (2 * blockSize) < cipher.length - messageDigestSize){
            BigInteger b = new BigInteger(1, Arrays.copyOfRange(cipher, cipherIndex, cipherIndex + blockSize));
            b = b.multiply(inverse).mod(publicKey.getP());
            setByte(dataSize, plainIndex, plain, b);
            messageDigest.update(b.toByteArray());
            cipherIndex += blockSize;
            plainIndex += dataSize;
        }
        byte[] hash = messageDigest.digest(pad.toByteArray());
        System.out.println("Decrypted : " + Arrays.toString(hash));
        if (Arrays.equals(hash, mess.toByteArray())){
            System.out.println("Message unverified!!");
            System.out.println("Sent : " + Arrays.toString(mess.toByteArray()));
            System.out.println("Hash : " + Arrays.toString(hash));
        }
        else {
            System.out.println("Message verified");
        }
        MultiFile multiFile = (MultiFile) Utilities.deserialize(plain);
        Files.write(Path.of(fileAttribute.getParent() + "\\3-" + multiFile.getFileName()), multiFile.getContent());
    }
    public RandomKey generateRandomKey(BigInteger p){
        BigInteger k;
        BigInteger min = BigInteger.TWO;
        BigInteger max = p.subtract(BigInteger.ONE);
        do {
            k = randomBigInt(min, max);
        }
        while (!max.gcd(k).equals(BigInteger.ONE));
        return new RandomKey(k);
    }
    private BigInteger genP(Set<BigInteger> primeFactor) {
        BigInteger p = BigInteger.ONE;
        for (BigInteger pi : primeFactor) {
            p = p.multiply(pi);
        }
        return p.add(BigInteger.ONE);
    }
    private BigInteger genQ(Set<BigInteger> primeFactor, BigInteger p) {
        BigInteger max = p.subtract(BigInteger.ONE);
        BigInteger min = BigInteger.TWO;
        BigInteger q;
        do {
            q = randomBigInt(min, max);
        }
        while (!isGenerator(q, primeFactor, p));
        return q;
    }
    private BigInteger genU(BigInteger p) {
        BigInteger min = BigInteger.TWO;
        BigInteger max = p.subtract(BigInteger.ONE);
        return randomBigInt(min, max);
    }
    private boolean isGenerator(BigInteger u, Set<BigInteger> pf, BigInteger p) {
        for (BigInteger pi : pf) {
            BigInteger expo = p.subtract(BigInteger.ONE).divide(pi);
            BigInteger mod = u.modPow(expo, p);
            if (mod.equals(BigInteger.ONE)) {
                return false;
            }
        }
        return true;
    }
    private Set<BigInteger> primeFactor(int keySize) {
        BigInteger min = BigInteger.TWO.pow(keySize -2);
        BigInteger max = BigInteger.TWO.pow(keySize -1).subtract(BigInteger.ONE);
        BigInteger avg = (min.add(max)).divide(BigInteger.TWO);
        BigInteger p = BigInteger.TWO;
        Set<BigInteger> primeFactors = new HashSet<>();
        primeFactors.add(p);
        do {
            BigInteger pf = randomBigInt(min, avg);
            if (pf.isProbablePrime(pf.bitLength())){
                BigInteger pp = p.multiply(pf).add(BigInteger.ONE);
                if (pp.isProbablePrime(pp.bitLength())){
                    primeFactors.add(pf);
                    p = pp;
                }
            }
        }
        while (p.equals(BigInteger.TWO));
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
//    public BigInteger fastExpo(BigInteger base, BigInteger expo, BigInteger p) {
//        char[] binary = expo.toString(2).toCharArray();
//        BigInteger res = BigInteger.ONE;
//        if (binary[binary.length -1] == '1') {
//            res = res.multiply(base).mod(p);
//        }
//        for (int i = binary.length -2; i > -1 ; i--) {
//            base = base.modPow(BigInteger.TWO, p);
//            if (binary[i] == '1'){
//                res = res.multiply(base).mod(p);
//            }
//        }
//        return res;
//    }


}
