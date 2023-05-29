package elgamal;
import org.w3c.dom.ls.LSOutput;
import utils.MultiFile;
import utils.Utilities;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

public class Elgamal {
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
    public void encryptFile(String path, String receiverPublic, String senderPublic, String senderPrivate) throws Exception {
        PublicKey receivPublicKey = (PublicKey) Utilities.deserialize(Files.readAllBytes(Path.of(receiverPublic)));
        PublicKey sendPublicKey = (PublicKey) Utilities.deserialize(Files.readAllBytes(Path.of(senderPublic)));
        PrivateKey sendPrivateKey = (PrivateKey) Utilities.deserialize(Files.readAllBytes(Path.of(senderPrivate)));
        encryptFile(path, receivPublicKey, sendPublicKey, sendPrivateKey);
    }
    public void encryptFile(String filePath, PublicKey receiverPublic, PublicKey senderPublic, PrivateKey senderPrivate) throws Exception {
//      TODO HASH OVERFLOW
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        BigInteger k = generateRandomKey(receiverPublic.getP()).getRandomKey();
        BigInteger a = receiverPublic.getQ().modPow(k, receiverPublic.getP());
        BigInteger ks = generateRandomKey(senderPublic.getP()).getRandomKey();
        BigInteger r = senderPublic.getQ().modPow(ks, senderPublic.getP());
        BigInteger multiB = receiverPublic.getY().modPow(k, receiverPublic.getP());
        messageDigest.update(a.toByteArray());
        Path fileAttribute = Paths.get(filePath);
        MultiFile multiFile = new MultiFile(fileAttribute.getFileName().toString(), Files.readAllBytes(fileAttribute.toAbsolutePath()));
        byte[] fileBytes = Utilities.serialize(multiFile);
        int blockSize = receiverPublic.getP().bitLength() / 8;
        int dataSize = blockSize - 1;
        int cipherSize = fileBytes.length / dataSize;
        int padSize = 0;
        if (fileBytes.length % dataSize != 0){
            padSize = blockSize;
        }
        //A + R + TEXT + PADDING + S
        byte[] cipher = new byte[blockSize + blockSize + (blockSize * cipherSize) + padSize + blockSize];
        int fileIndex = 0;
        int cipherIndex = 0;
        //ADD A
        setByte(blockSize, cipherIndex, cipher, a);
        cipherIndex += blockSize;
        //ADD R
        setByte(blockSize, cipherIndex, cipher, r);
        cipherIndex += blockSize;
        while (fileIndex < fileBytes.length - dataSize ) {
            BigInteger data = new BigInteger(1, Arrays.copyOfRange(fileBytes, fileIndex, fileIndex + dataSize));
            messageDigest.update(data.toByteArray());
            encryptByte(receiverPublic.getP(), data, multiB, blockSize, cipherIndex, cipher);
            fileIndex+= dataSize;
            cipherIndex += blockSize;
        }
        //ADD PADDING
        if (fileBytes.length % dataSize != 0){
            BigInteger data = new BigInteger(1, Arrays.copyOfRange(fileBytes, fileIndex, fileIndex + (fileBytes.length % dataSize)));
            encryptByte(receiverPublic.getP(), data, multiB, blockSize, cipherIndex, cipher);
            messageDigest.update(data.toByteArray());
            cipherIndex += blockSize;
        }
        //ADD S
        BigInteger mess = new BigInteger(1, Arrays.copyOfRange(messageDigest.digest(), 0 , messageDigest.getDigestLength()));
        mess = ((ks.modInverse(senderPublic.getP().subtract(BigInteger.ONE))).multiply(mess.subtract(senderPrivate.getU().multiply(r)))).mod(senderPublic.getP().subtract(BigInteger.ONE));
        //TODO S OVERFLOW
//        encryptByte(receiverPublic.getP(), mess, multiB, blockSize, cipherIndex, cipher);
        setByte(blockSize, cipherIndex, cipher, mess);
        Files.write(Path.of(fileAttribute.getParent() + "\\" + fileAttribute.getFileName().toString().split("\\.")[0] + ".encrypted"), cipher);
    }
    public void encryptByte(BigInteger p, BigInteger data, BigInteger multiB, int blockSize, int cipherIndex, byte[] cipher) {
        BigInteger b = (multiB.multiply(data)).mod(p);
        setByte(blockSize, cipherIndex, cipher, b);
    }
    public void setByte(int blockSize, int index, byte[] cipher, BigInteger n) {
        if (n.toByteArray().length > blockSize){
            System.arraycopy(n.toByteArray(), 1, cipher, index, blockSize);
        }
        else {
            int startAt = blockSize - n.toByteArray().length;
            System.arraycopy(n.toByteArray(), 0, cipher, index + startAt, n.toByteArray().length);
        }
    }
    public void decryptFile(String path, String senderPublic, String receiverPublic, String receiverPrivate) throws IOException, NoSuchAlgorithmException, ClassNotFoundException {
        PublicKey sendPublic = (PublicKey) Utilities.deserialize(Files.readAllBytes(Path.of(senderPublic)));
        PublicKey receivePublic = (PublicKey) Utilities.deserialize(Files.readAllBytes(Path.of(receiverPublic)));
        PrivateKey receivePrivate = (PrivateKey) Utilities.deserialize(Files.readAllBytes(Path.of(receiverPrivate)));
        decryptFile(path, sendPublic, receivePublic, receivePrivate);
    }
    public void decryptFile(String filePath, PublicKey senderPublic, PublicKey receiverPublic, PrivateKey receiverPrivate) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        Path fileAttribute = Paths.get(filePath);
        byte[] cipher = Files.readAllBytes(fileAttribute.toAbsolutePath());
        int blockSize = receiverPublic.getP().bitLength() / 8;
        int dataSize  = blockSize - 1;
        int plainSize = ((cipher.length / blockSize) - 4) * dataSize;
        BigInteger    a = new BigInteger(1, Arrays.copyOfRange(cipher, 0, blockSize));
        BigInteger    r = new BigInteger(1, Arrays.copyOfRange(cipher, blockSize,  2 * blockSize));
        System.out.println("r : " + Arrays.toString(r.toByteArray()));

        BigInteger  pad = new BigInteger(1, Arrays.copyOfRange(cipher, cipher.length - (2 * blockSize), cipher.length - blockSize));
        BigInteger mess = new BigInteger(1, Arrays.copyOfRange(cipher, cipher.length - blockSize, cipher.length));
        BigInteger inverse = a.modPow(receiverPrivate.getU(), receiverPublic.getP()).modInverse(receiverPublic.getP());
        pad  = pad.multiply(inverse).mod(receiverPublic.getP());
//        mess = mess.multiply(inverse).mod(receiverPublic.getP());
        System.out.println("S : " + Arrays.toString(mess.toByteArray()));
        int padSize = pad.toByteArray().length;
        if (pad.toByteArray()[0] == 0) {
            padSize -= 1;
        }
        byte[] plain = new byte[plainSize + padSize];
        setPadByte(plain, pad);
        messageDigest.update(a.toByteArray());
        int cipherIndex =  2 * blockSize;
        int plainIndex = 0;
        while (cipherIndex + blockSize < cipher.length - blockSize){
            BigInteger b = new BigInteger(1, Arrays.copyOfRange(cipher, cipherIndex, cipherIndex + blockSize));
            b = b.multiply(inverse).mod(receiverPublic.getP());
            setByte(dataSize, plainIndex, plain, b);
            messageDigest.update(b.toByteArray());
            cipherIndex += blockSize;
            plainIndex += dataSize;
        }
        byte[] hash = messageDigest.digest(pad.toByteArray());
        BigInteger qx = senderPublic.getQ().modPow(new BigInteger(1, hash), senderPublic.getP());
        BigInteger yr = senderPublic.getY().modPow(r, senderPublic.getP());
        BigInteger rs = r.modPow(mess, senderPublic.getP());
        if (qx.equals((yr.multiply(rs)).mod(senderPublic.getP()))){
            System.out.println("Message verified");
            System.out.println("qu     : " + qx);
            System.out.println("yr*rs  : " + (yr.multiply(rs)).mod(senderPublic.getP()));
            MultiFile multiFile = (MultiFile) Utilities.deserialize(plain);
            Files.write(Path.of(fileAttribute.getParent() + "\\decrypted-" + multiFile.getFileName()), multiFile.getContent());
        }
        else {
            System.out.println("Message unverified!!");
            System.out.println("qu     : " + qx);
            System.out.println("yr*rs  : " + (yr.multiply(rs)).mod(senderPublic.getP()));
        }
    }
    private void setPadByte(byte[] plain, BigInteger pad) {
        byte[] padByte = pad.toByteArray();
        if (pad.toByteArray()[0] == 0){
            padByte = Arrays.copyOfRange(pad.toByteArray(), 1, pad.toByteArray().length);
        }
        System.arraycopy(padByte, 0, plain, plain.length - padByte.length, padByte.length);
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
    public BigInteger genP(Set<BigInteger> primeFactor) {
        BigInteger p = BigInteger.ONE;
        for (BigInteger pi : primeFactor) {
            p = p.multiply(pi);
        }
        return p.add(BigInteger.ONE);
    }
    public BigInteger genQ(Set<BigInteger> primeFactor, BigInteger p) {
        BigInteger max = p.subtract(BigInteger.ONE);
        BigInteger min = BigInteger.TWO;
        BigInteger q;
        do {
            q = randomBigInt(min, max);
        }
        while (!isGenerator(q, primeFactor, p));
        return q;
    }
    public BigInteger genU(BigInteger p) {
        BigInteger min = BigInteger.TWO;
        BigInteger max = p.subtract(BigInteger.ONE);
        return randomBigInt(min, max);
    }
    public boolean isGenerator(BigInteger u, Set<BigInteger> pf, BigInteger p) {
        for (BigInteger pi : pf) {
            BigInteger expo = p.subtract(BigInteger.ONE).divide(pi);
            BigInteger mod = u.modPow(expo, p);
            if (mod.equals(BigInteger.ONE)) {
                return false;
            }
        }
        return true;
    }
    public Set<BigInteger> primeFactor(int keySize) {
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
    public BigInteger randomBigInt(BigInteger minLimit, BigInteger maxLimit) {
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

    public BigInteger randomBigInt(int bytesSpace){
        SecureRandom secureRandom = new SecureRandom();
        return new BigInteger(1, secureRandom.generateSeed(bytesSpace));
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
