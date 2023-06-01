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
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

public class Elgamal2 {
    public KeyPair generateKeyPair(int keySize) {
        BigInteger p = genP(keySize);
        BigInteger q = genQ(p);
        BigInteger u = genU(p);
        BigInteger y = q.modPow(u, p);
        PublicKey publicKey = new PublicKey(p, q, y);
        PrivateKey privateKey = new PrivateKey(u);
        return new KeyPair(publicKey, privateKey);
    }
    public void encryptFile(String filePath, String receiverPublic, String senderKeyPair, String signAlgorithm) throws Exception {
        PublicKey receivPublicKey = (PublicKey) Utilities.deserialize(Files.readAllBytes(Path.of(receiverPublic)));
        KeyPair keyPair = (KeyPair) Utilities.deserialize(Files.readAllBytes(Path.of(senderKeyPair)));
        PublicKey sendPublicKey = keyPair.getPublicKey();
        PrivateKey sendPrivateKey = keyPair.getPrivateKey();
        MessageDigest messageDigest = MessageDigest.getInstance(signAlgorithm);
        encryptFile(filePath, receivPublicKey, sendPublicKey, sendPrivateKey, messageDigest);
    }
    public void encryptFile(String filePath, PublicKey receiverPublic, PublicKey senderPublic, PrivateKey senderPrivate, MessageDigest messageDigest) throws Exception {
        if (senderPublic.getP().toByteArray().length < messageDigest.getDigestLength()){
            throw new Exception("Invalid!! The key size is less than sign!!");
        }
        BigInteger k = generateRandomKey(receiverPublic.getP()).getRandomKey();
        BigInteger a = receiverPublic.getQ().modPow(k, receiverPublic.getP());
        BigInteger multiB = receiverPublic.getY().modPow(k, receiverPublic.getP());
        BigInteger b;
        messageDigest.update(a.toByteArray());
        BigInteger ks = generateRandomKey(senderPublic.getP()).getRandomKey();
        BigInteger r = senderPublic.getQ().modPow(ks, senderPublic.getP());
        messageDigest.update(r.toByteArray());
        Path fileAttribute = Paths.get(filePath);
        MultiFile multiFile = new MultiFile(fileAttribute.getFileName().toString(), Files.readAllBytes(fileAttribute.toAbsolutePath()));
        byte[] fileBytes = Utilities.serialize(multiFile);
        int blockSize = receiverPublic.getP().bitLength() / 8;
        int dataSize = blockSize - 1;
        int padSize = 0;
        if (fileBytes.length % dataSize != 0){
            padSize = blockSize;
        }
        //A + R + TEXT + PADDING + S
        byte[] cipher = new byte[(3 * blockSize) + (blockSize * (fileBytes.length / dataSize)) + padSize];
        int fileIndex = 0;
        int cipherIndex = 0;
        padSize = fileBytes.length % dataSize;
        //ADD A
        setByte(blockSize, cipherIndex, cipher, a);
        cipherIndex += blockSize;
        //ADD R
        setByte(blockSize, cipherIndex, cipher, r);
        cipherIndex += blockSize;
        //ADD PADDING
        if (fileBytes.length % dataSize != 0){
            int from = fileBytes.length - padSize;
            b = new BigInteger(1, Arrays.copyOfRange(fileBytes, from, fileBytes.length));
            a = (a.add(BigInteger.ONE)).mod(receiverPublic.getP());
            b = b.xor(a);
            messageDigest.update(b.toByteArray());
            encryptByte(receiverPublic.getP(), b, multiB, blockSize, cipher.length - (2 * blockSize), cipher);
        }
        while (fileIndex < fileBytes.length - padSize ) {
            b = new BigInteger(1, Arrays.copyOfRange(fileBytes, fileIndex, fileIndex + dataSize));
            a = (a.add(BigInteger.ONE)).mod(receiverPublic.getP());
            b = b.xor(a);
            messageDigest.update(b.toByteArray());
            encryptByte(receiverPublic.getP(), b, multiB, blockSize, cipherIndex, cipher);
            fileIndex+= dataSize;
            cipherIndex += blockSize;
        }
        //ADD S
        b = new BigInteger(1, Arrays.copyOfRange(messageDigest.digest(), 0 , messageDigest.getDigestLength()));
        b = ((ks.modInverse(senderPublic.getP().subtract(BigInteger.ONE))).multiply(b.subtract(senderPrivate.getU().multiply(r)))).mod(senderPublic.getP().subtract(BigInteger.ONE));
        setByte(blockSize, cipherIndex + blockSize, cipher, b);
        Files.write(Path.of(fileAttribute.getParent() + "\\encrypted-" + fileAttribute.getFileName().toString().split("\\.")[0] + ".encrypted"), cipher);
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
    public void decryptFile(String filePath, String senderPublic, String receiverKeyPair, String signAlgorithm) throws Exception {
        PublicKey senderPublicKey = (PublicKey) Utilities.deserialize(Files.readAllBytes(Path.of(senderPublic)));
        KeyPair keyPair = (KeyPair) Utilities.deserialize(Files.readAllBytes(Path.of(receiverKeyPair)));
        PublicKey receivPublicKey = keyPair.getPublicKey();
        PrivateKey receivPrivateKey = keyPair.getPrivateKey();
        MessageDigest messageDigest = MessageDigest.getInstance(signAlgorithm);
        decryptFile(filePath, senderPublicKey, receivPublicKey, receivPrivateKey, messageDigest);
    }
    public void decryptFile(String filePath, PublicKey senderPublic, PublicKey receiverPublic, PrivateKey receiverPrivate, MessageDigest messageDigest) throws Exception {
        if (senderPublic.getP().toByteArray().length < messageDigest.getDigestLength()){
            throw new Exception("Invalid!! The key size is less than sign!!");
        }
        Path fileAttribute = Paths.get(filePath);
        byte[] cipher = Files.readAllBytes(fileAttribute.toAbsolutePath());
        int blockSize = receiverPublic.getP().bitLength() / 8;
        int dataSize  = blockSize - 1;
        int plainSize = ((cipher.length / blockSize) - 4) * dataSize;
        BigInteger    a = new BigInteger(1, Arrays.copyOfRange(cipher, 0, blockSize));
        BigInteger    r = new BigInteger(1, Arrays.copyOfRange(cipher, blockSize,  2 * blockSize));
        BigInteger  pad = new BigInteger(1, Arrays.copyOfRange(cipher, cipher.length - (2 * blockSize), cipher.length - blockSize));
        BigInteger mess = new BigInteger(1, Arrays.copyOfRange(cipher, cipher.length - blockSize, cipher.length));
        BigInteger inverse = a.modPow(receiverPrivate.getU(), receiverPublic.getP()).modInverse(receiverPublic.getP());
        messageDigest.update(a.toByteArray());
        messageDigest.update(r.toByteArray());
        pad  = pad.multiply(inverse).mod(receiverPublic.getP());
        messageDigest.update(pad.toByteArray());
        a    = (a.add(BigInteger.ONE)).mod(receiverPublic.getP());
        pad  = pad.xor(a);
        int padSize = pad.toByteArray().length;
        if (pad.toByteArray()[0] == 0) {
            padSize -= 1;
        }
        byte[] plain = new byte[plainSize + padSize];
        int cipherIndex =  2 * blockSize;
        int plainIndex = 0;
        setPadByte(plain, pad);
        while (cipherIndex + blockSize < cipher.length - blockSize){
            BigInteger b = new BigInteger(1, Arrays.copyOfRange(cipher, cipherIndex, cipherIndex + blockSize));
            b = b.multiply(inverse).mod(receiverPublic.getP());
            messageDigest.update(b.toByteArray());
            a = (a.add(BigInteger.ONE)).mod(receiverPublic.getP());
            b = b.xor(a);
            setByte(dataSize, plainIndex, plain, b);
            cipherIndex += blockSize;
            plainIndex += dataSize;
//            BigInteger a2 = a.modPow(receiverPrivate.getU(), receiverPublic.getP()).modInverse(receiverPublic.getP());
        }
        byte[] hash = messageDigest.digest();
        BigInteger qx = senderPublic.getQ().modPow(new BigInteger(1, hash), senderPublic.getP());
        BigInteger yr = senderPublic.getY().modPow(r, senderPublic.getP());
        BigInteger rs = r.modPow(mess, senderPublic.getP());
        if (qx.equals((yr.multiply(rs)).mod(senderPublic.getP()))){
            System.out.println("==== Message verified =====");
            System.out.println("qu     : " + qx);
            System.out.println("yr*rs  : " + (yr.multiply(rs)).mod(senderPublic.getP()));
            MultiFile multiFile = (MultiFile) Utilities.deserialize(plain);
            Files.write(Path.of(fileAttribute.getParent() + "\\decrypted-" + multiFile.getFileName()), multiFile.getContent());
        }
        else {
            System.out.println("==== Message unverified!! ====");
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
    public BigInteger genP(int keySpace) {
        BigInteger max = BigInteger.TWO.pow(keySpace).subtract(BigInteger.ONE);
        BigInteger min = BigInteger.TWO.pow(keySpace -1);
        BigInteger p ;
        do {
            p = randomBigInt(min, max);
        }
        while (!p.isProbablePrime(p.bitLength()));
        return p;
    }
    public BigInteger genQ(BigInteger p) {
        BigInteger max = p.subtract(BigInteger.ONE);
        BigInteger min = BigInteger.TWO;
        BigInteger q = randomBigInt(min, max);
        if (!isGenerator(q, p)){
            q = q.negate().mod(p);
        }
        return q;
    }
    public BigInteger genU(BigInteger p) {
        BigInteger min = BigInteger.TWO;
        BigInteger max = p.subtract(BigInteger.ONE);
        return randomBigInt(min, max);
    }
    public boolean isGenerator(BigInteger q, BigInteger p) {
        BigInteger expo = (p.subtract(BigInteger.ONE)).divide(BigInteger.TWO);
        return !q.modPow(expo, p).equals(BigInteger.ONE);
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
    public boolean isPrime(BigInteger n, int loop) {
//        BigInteger sqrt = n.sqrt();
        for (int i = 0; i < loop; i++) {
            BigInteger randomNum = randomBigInt(BigInteger.TWO, n.subtract(BigInteger.ONE));
            BigInteger gcd = randomNum.gcd(n);
            BigInteger expo = (n.subtract(BigInteger.ONE)).divide(BigInteger.TWO);
            if (randomNum.modPow(expo, n).equals(BigInteger.ONE) || randomNum.modPow(expo, n).equals(BigInteger.ONE.negate())){
                continue;
            }
            else if (gcd.compareTo(BigInteger.ONE) > 0){
                return false;
            }
            else {
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


}
