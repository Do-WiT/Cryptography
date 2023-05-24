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

public class ElgamalV2 {
    public KeyPair generateKeyPair(int keySize) {
        Set<BigInteger> primeFactors = primeFactor(keySize);
        BigInteger p = genP(primeFactors);
        BigInteger q = genQ(primeFactors, p);
        BigInteger u = genU(p);
        BigInteger y = fastExpo(q, u, p);
        PublicKey publicKey = new PublicKey(p, q, y);
        PrivateKey privateKey = new PrivateKey(u);
        return new KeyPair(publicKey, privateKey);
    }
    public void encryptFile(String filePath, PublicKey publicKey) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
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
        BigInteger multiB = fastExpo(publicKey.getY(), randomKey.getRandomKey(), publicKey.getP());
        BigInteger a = fastExpo(publicKey.getQ(), randomKey.getRandomKey(), publicKey.getP());
        messageDigest.update(a.toByteArray());
        //PADDING + A (No SIGNATURE)
        byte[] cipher = new byte[(blockSize * cipherSize) + padSize + blockSize + messageDigest.getDigestLength()];
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
        setByte(blockSize, cipherIndex, cipher, a);
        cipherIndex += blockSize;
        byte[] mess = Arrays.copyOfRange(messageDigest.digest(), 0 , messageDigest.getDigestLength());
        System.out.println("Encrypted : " + Arrays.toString(mess));
        setByte(messageDigest.getDigestLength(), cipherIndex, cipher, new BigInteger(1, mess));
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
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        Path fileAttribute = Paths.get(filePath);
        byte[] cipher = Files.readAllBytes(fileAttribute.toAbsolutePath());
        int blockSize = publicKey.getP().toByteArray().length -1;
        int dataSize = blockSize - 1;
        int messageDigestSize = messageDigest.getDigestLength();
        int plainSize = (((cipher.length - messageDigestSize) / blockSize) -2) * dataSize;
        BigInteger a = new BigInteger(1, Arrays.copyOfRange(cipher, cipher.length - blockSize - messageDigestSize, cipher.length - messageDigestSize));
        BigInteger b = new BigInteger(1, Arrays.copyOfRange(cipher, cipher.length - (2 * blockSize) - messageDigestSize, cipher.length - blockSize - messageDigestSize));
        BigInteger inverse = fastExpo(a, privateKey.getU(), publicKey.getP()).modInverse(publicKey.getP());
        BigInteger pad = b.multiply(inverse).mod(publicKey.getP());
        int padSize = pad.toByteArray().length;
        byte[] plain = new byte[plainSize + padSize];
        if (pad.toByteArray().length ==  dataSize){
            System.arraycopy(pad.toByteArray(), 0, plain, plain.length - dataSize , dataSize);
        }
        else if (pad.toByteArray().length > dataSize) {
            System.arraycopy(pad.toByteArray(), 1, plain, plain.length - dataSize, dataSize);
        }
        else {// <
            int startAt = Math.abs(pad.toByteArray().length - dataSize);
            System.arraycopy(pad.toByteArray(), 0, plain, plain.length - dataSize + startAt, pad.toByteArray().length);
        }
        messageDigest.update(a.toByteArray());
        int cipherIndex = 0;
        int plainIndex = 0;
        while (cipherIndex + (2 * blockSize) < cipher.length - messageDigestSize){
            b = new BigInteger(1, Arrays.copyOfRange(cipher, cipherIndex, cipherIndex + blockSize));
            b = b.multiply(inverse).mod(publicKey.getP());
            messageDigest.update(b.toByteArray());
            if (b.toByteArray().length ==  dataSize){
                System.arraycopy(b.toByteArray(), 0, plain, plainIndex, dataSize);
            }
            else if (b.toByteArray().length > dataSize) {
                System.arraycopy(b.toByteArray(), 1, plain, plainIndex, dataSize);
            }
            else {// <
                int startAt = Math.abs(b.toByteArray().length - dataSize);
                System.arraycopy(b.toByteArray(), 0, plain, plainIndex + startAt, b.toByteArray().length);
            }
            cipherIndex += blockSize;
            plainIndex += dataSize;
        }
        messageDigest.update(pad.toByteArray());
        System.out.println("Decrypted : " + Arrays.toString(messageDigest.digest()));
        MultiFile multiFile = (MultiFile) Utilities.deserialize(plain);
        Files.write(Path.of(fileAttribute.getParent() + "\\2-" + multiFile.getFileName()), multiFile.getContent());
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
            BigInteger mod = fastExpo(u, expo, p);
            if (mod.equals(BigInteger.ONE)) {
                return false;
            }
        }
        return true;
    }
    public BigInteger fastExpo(BigInteger base, BigInteger expo, BigInteger p) {
        char[] binary = expo.toString(2).toCharArray();
        BigInteger res = BigInteger.ONE;
        if (binary[binary.length -1] == '1') {
            res = res.multiply(base).mod(p);
        }
        for (int i = binary.length -2; i > -1 ; i--) {
            base = base.modPow(BigInteger.TWO, p);
            if (binary[i] == '1'){
                res = res.multiply(base).mod(p);
            }
        }
        return res;
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

    //    public void encryptFile(String filePath, PublicKey publicKey) throws Exception {
//        RandomKey randomKey = generateRandomKey(publicKey.getP());
//        Path fileAttribute = Paths.get(filePath);
//        MultiFile multiFile = new MultiFile(fileAttribute.getFileName().toString(), Files.readAllBytes(fileAttribute.toAbsolutePath()));
//        byte[] fileBytes = Utilities.serialize(multiFile);
//        int blockSize = publicKey.getP().toByteArray().length -1;
//        int dataSize = blockSize - 1;
//        int cipherSize = fileBytes.length / dataSize;
//        int padSize = 0;
//        if (fileBytes.length % dataSize != 0){
//            padSize = blockSize;
//        }
//        BigInteger multiB = fastExpo(publicKey.getY(), randomKey.getRandomKey(), publicKey.getP());
//        BigInteger a = fastExpo(publicKey.getQ(), randomKey.getRandomKey(), publicKey.getP());
//        // PADDING + A (No SIGNATURE)
//        byte[] cipher = new byte[(blockSize * cipherSize) + padSize + blockSize];
//        int fileIndex = 0;
//        int cipherIndex = 0;
//        while (fileIndex < fileBytes.length - dataSize) {
//            BigInteger data = new BigInteger(1, Arrays.copyOfRange(fileBytes, fileIndex, fileIndex + dataSize));
//            BigInteger b =  (multiB.multiply(data)).mod(publicKey.getP());
//            if (b.toByteArray().length > blockSize){
//                System.arraycopy(b.toByteArray(), 1, cipher, cipherIndex, blockSize);
//            }
//            else if (b.toByteArray().length < blockSize){
//                int startAt = Math.abs(b.toByteArray().length - blockSize);
//                System.arraycopy(b.toByteArray(), 0, cipher, cipherIndex + startAt, b.toByteArray().length);
//            }
//            else {
//                System.arraycopy(b.toByteArray(), 0, cipher, cipherIndex, blockSize);
//            }
//            fileIndex += dataSize;
//            cipherIndex += blockSize;
//        }
//        //ADD PADDING
//        if (fileBytes.length % dataSize != 0){
//            BigInteger data = new BigInteger(1, Arrays.copyOfRange(fileBytes, fileIndex, fileIndex + (fileBytes.length % dataSize)));
//            BigInteger b =  (multiB.multiply(data)).mod(publicKey.getP());
//            if (b.toByteArray().length > blockSize){
//                System.arraycopy(b.toByteArray(), 1, cipher, cipherIndex, blockSize);
//            }
//            else if (b.toByteArray().length < blockSize){
//                int startAt = Math.abs(b.toByteArray().length - blockSize);
//                System.arraycopy(b.toByteArray(), 0, cipher, cipherIndex + startAt, b.toByteArray().length);
//            }
//            else {
//                System.arraycopy(b.toByteArray(), 0, cipher, cipherIndex, blockSize);
//            }
//
//            cipherIndex += blockSize;
//        }
//        if (a.toByteArray().length > blockSize){
//            System.arraycopy(a.toByteArray(), 1, cipher, cipherIndex, blockSize);
//        }
//        else if (a.toByteArray().length < blockSize){
//            int startAt = Math.abs(a.toByteArray().length - blockSize);
//            System.arraycopy(a.toByteArray(), 0, cipher, cipherIndex + startAt, a.toByteArray().length);
//        }
//        else {
//            System.arraycopy(a.toByteArray(), 0, cipher, cipherIndex, blockSize);
//        }
//        Files.write(Path.of(fileAttribute.getParent() + "\\" +"file.encrypted"), cipher);
//    }
//    public void decryptFile(String filePath, PrivateKey privateKey, PublicKey publicKey) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
//        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
//        Path fileAttribute = Paths.get(filePath);
//        byte[] cipher = Files.readAllBytes(fileAttribute.toAbsolutePath());
//        int blockSize = publicKey.getP().toByteArray().length -1;
//        int dataSize = blockSize - 1;
//        int plainSize = ((cipher.length / blockSize) -2) * dataSize;
//
//        BigInteger a = new BigInteger(1, Arrays.copyOfRange(cipher, cipher.length - blockSize, cipher.length));
//        BigInteger b = new BigInteger(1, Arrays.copyOfRange(cipher, cipher.length - (2 * blockSize), cipher.length - blockSize));
//        BigInteger res = fastExpo(a, privateKey.getU(), publicKey.getP()).modInverse(publicKey.getP());
//        res = b.multiply(res).mod(publicKey.getP());
//        int pad = res.toByteArray().length;
//        byte[] plain = new byte[plainSize + pad];
//        if (res.toByteArray().length ==  dataSize){
//            System.arraycopy(res.toByteArray(), 0, plain, plain.length - dataSize , dataSize);
//        }
//        else if (res.toByteArray().length > dataSize) {
//            System.arraycopy(res.toByteArray(), 1, plain, plain.length - dataSize, dataSize);
//        }
//        else {// <
//            int startAt = Math.abs(res.toByteArray().length - dataSize);
//            System.arraycopy(res.toByteArray(), 0, plain, plain.length - dataSize + startAt, res.toByteArray().length);
//        }
//        messageDigest.update(a.toByteArray());
//        int cipherIndex = 0;
//        int plainIndex = 0;
//        while (cipherIndex + (2 * blockSize) < cipher.length){
//            b = new BigInteger(1, Arrays.copyOfRange(cipher, cipherIndex, cipherIndex + blockSize));
//            res = fastExpo(a, privateKey.getU(), publicKey.getP()).modInverse(publicKey.getP());
//            res = b.multiply(res).mod(publicKey.getP());
////            System.out.println("res  : " + Arrays.toString(res.toByteArray()));
//            messageDigest.update(res.toByteArray());
//            if (res.toByteArray().length ==  dataSize){
//                System.arraycopy(res.toByteArray(), 0, plain, plainIndex, dataSize);
//            }
//            else if (res.toByteArray().length > dataSize) {
//                System.arraycopy(res.toByteArray(), 1, plain, plainIndex, dataSize);
//            }
//            else {// <
//                int startAt = Math.abs(res.toByteArray().length - dataSize);
//                System.arraycopy(res.toByteArray(), 0, plain, plainIndex + startAt, res.toByteArray().length);
//            }
//            cipherIndex += blockSize;
//            plainIndex += dataSize;
//        }
//        MultiFile multiFile = (MultiFile) Utilities.deserialize(plain);
//        Files.write(Path.of(fileAttribute.getParent() + "\\2-" + multiFile.getFileName()), multiFile.getContent());
//        System.out.println("Message Digest : " + Arrays.toString(messageDigest.digest()));
//    }

}
