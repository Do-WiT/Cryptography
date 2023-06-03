package elgamal;
import utils.MultiFile;
import utils.Utilities;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;

import static java.nio.file.Files.readAllBytes;

public class Elgamal4 {
    public KeyPair generateKeyPair(int keySize) {
        BigInteger p = genP(keySize);
        BigInteger q = genQ(p);
        BigInteger u = genU(p);
        BigInteger y = fastExpo(q, u, p);
        PublicKey publicKey = new PublicKey(p, q, y);
        PrivateKey privateKey = new PrivateKey(u);
        return new KeyPair(publicKey, privateKey);
    }
    public void encryptFile(String filePath, String receiverPublic, String senderKeyPair, String hashAlgorithm) throws Exception {
        PublicKey receivPublicKey = (PublicKey) Utilities.deserialize(readAllBytes(Path.of(receiverPublic)));
        KeyPair keyPair = (KeyPair) Utilities.deserialize(readAllBytes(Path.of(senderKeyPair)));
        PublicKey sendPublicKey = keyPair.getPublicKey();
        PrivateKey sendPrivateKey = keyPair.getPrivateKey();
        MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm);
        encryptFile(filePath, receivPublicKey, sendPublicKey, sendPrivateKey, messageDigest);
    }
    public void encryptFile(String filePath, PublicKey receiverPublic, PublicKey senderPublic, PrivateKey senderPrivate, MessageDigest messageDigest) throws Exception {
        if (senderPublic.getP().toByteArray().length < messageDigest.getDigestLength()){
            throw new Exception("Invalid!! The key size is less than sign!!");
        }
        BigInteger k = generateRandomKey(receiverPublic.getP()).getRandomKey();
        BigInteger a = fastExpo(receiverPublic.getQ(), k, receiverPublic.getP());
        BigInteger multiB = fastExpo(receiverPublic.getY(), k, receiverPublic.getP());
        BigInteger b;
        messageDigest.update(a.toByteArray());
        BigInteger ks = generateRandomKey(senderPublic.getP()).getRandomKey();
        BigInteger r = fastExpo(senderPublic.getQ(), ks, senderPublic.getP());
        messageDigest.update(r.toByteArray());
        Path fileAttribute = Paths.get(filePath);
        MultiFile multiFile = new MultiFile(fileAttribute.getFileName().toString(), readAllBytes(fileAttribute.toAbsolutePath()));
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
    public void decryptFile(String filePath, String receiverKeyPair) throws Exception {
        KeyPair keyPair = (KeyPair) Utilities.deserialize(readAllBytes(Path.of(receiverKeyPair)));
        PublicKey receivPublicKey = keyPair.getPublicKey();
        PrivateKey receivPrivateKey = keyPair.getPrivateKey();
        decryptFile(filePath, receivPublicKey, receivPrivateKey);
    }
    public void decryptFile(String filePath, PublicKey receiverPublic, PrivateKey receiverPrivate) throws Exception {
        Path fileAttribute = Paths.get(filePath);
        byte[] cipher = readAllBytes(fileAttribute.toAbsolutePath());
        int blockSize = receiverPublic.getP().bitLength() / 8;
        int dataSize  = blockSize - 1;
        int plainSize = ((cipher.length / blockSize) - 4) * dataSize;
        BigInteger    a = new BigInteger(1, Arrays.copyOfRange(cipher, 0, blockSize));
        BigInteger  pad = new BigInteger(1, Arrays.copyOfRange(cipher, cipher.length - (2 * blockSize), cipher.length - blockSize));
        BigInteger inverse = fastExpo(a, receiverPrivate.getU(), receiverPublic.getP()).modInverse(receiverPublic.getP());
        pad  = pad.multiply(inverse).mod(receiverPublic.getP());
        a    = (a.add(BigInteger.ONE)).mod(receiverPublic.getP());
        pad  = pad.xor(a);
        int padSize = pad.toByteArray().length;
        if (pad.toByteArray()[0] == 0) {
            padSize -= 1;
        }
        byte[] plain = new byte[plainSize + padSize];
        int cipherIndexFrom = 2 * blockSize;
        int cipherIndexTo   = cipher.length - (2 * blockSize);
        int plainIndex = 0;
        setPadByte(plain, pad);
        while (cipherIndexFrom < cipherIndexTo){
            BigInteger b = new BigInteger(1, Arrays.copyOfRange(cipher, cipherIndexFrom, cipherIndexFrom + blockSize));
            b = b.multiply(inverse).mod(receiverPublic.getP());
            a = (a.add(BigInteger.ONE)).mod(receiverPublic.getP());
            b = b.xor(a);
            setByte(dataSize, plainIndex, plain, b);
            cipherIndexFrom += blockSize;
            plainIndex += dataSize;
        }
        MultiFile multiFile = (MultiFile) Utilities.deserialize(plain);
        Files.write(Path.of(fileAttribute.getParent() + "\\d-" + multiFile.getFileName()), multiFile.getContent());
    }
    private void setPadByte(byte[] plain, BigInteger pad) {
        byte[] padByte = pad.toByteArray();
        if (pad.toByteArray()[0] == 0){
            padByte = Arrays.copyOfRange(pad.toByteArray(), 1, pad.toByteArray().length);
        }
        System.arraycopy(padByte, 0, plain, plain.length - padByte.length, padByte.length);
    }

    public void verifyMessage(String filePath, String senderPublic, String receiverKeyPair, String hashAlgorithm) throws Exception{
        PublicKey senderPublicKey = (PublicKey) Utilities.deserialize(readAllBytes(Path.of(senderPublic)));
        KeyPair keyPair = (KeyPair) Utilities.deserialize(readAllBytes(Path.of(receiverKeyPair)));
        PublicKey receivPublicKey = keyPair.getPublicKey();
        PrivateKey receivPrivateKey = keyPair.getPrivateKey();
        MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm);
        verifyMessage(filePath, senderPublicKey, receivPublicKey, receivPrivateKey, messageDigest);
    }
    public void verifyMessage(String filePath, PublicKey senderPublic, PublicKey receiverPublic, PrivateKey receiverPrivate, MessageDigest messageDigest) throws Exception{
        if (senderPublic.getP().toByteArray().length < messageDigest.getDigestLength()){
            throw new Exception("Invalid!! The key size is less than sign!!");
        }
        Path fileAttribute = Paths.get(filePath);
        byte[] cipher = readAllBytes(fileAttribute.toAbsolutePath());
        int blockSize = receiverPublic.getP().bitLength() / 8;
        BigInteger a = new BigInteger(1, Arrays.copyOfRange(cipher, 0, blockSize));
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(cipher, blockSize, 2 * blockSize));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(cipher, cipher.length - blockSize, cipher.length));
        BigInteger inverse = fastExpo(a, receiverPrivate.getU(), receiverPublic.getP()).modInverse(receiverPublic.getP());
        BigInteger b;
        messageDigest.update(a.toByteArray());
        messageDigest.update(r.toByteArray());
        int cipherIndexFrom = 2 * blockSize;
        int cipherIndexTo   = cipher.length - (2 * blockSize);
        b = new BigInteger(1, Arrays.copyOfRange(cipher, cipher.length - (2 * blockSize) , cipher.length - blockSize));
        b = b.multiply(inverse).mod(receiverPublic.getP());
        messageDigest.update(b.toByteArray());
        while (cipherIndexFrom < cipherIndexTo){
            b = new BigInteger(1, Arrays.copyOfRange(cipher, cipherIndexFrom, cipherIndexFrom + blockSize));
            b = b.multiply(inverse).mod(receiverPublic.getP());
            messageDigest.update(b.toByteArray());
            cipherIndexFrom += blockSize;
        }
        byte[] hash = messageDigest.digest();
        BigInteger qu = fastExpo(senderPublic.getQ(), new BigInteger(1, hash), senderPublic.getP());
        BigInteger yr = fastExpo(senderPublic.getY(), r, senderPublic.getP());
        BigInteger rs = fastExpo(r, s, senderPublic.getP());
        if (qu.equals((yr.multiply(rs)).mod(senderPublic.getP()))){
            System.out.println("==== Message verified =====");
        }
        else {
            System.out.println("==== Message unverified!! ====");
        }
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
        BigInteger safeP;
        do {
            p = randomBigInt(min, max);
            safeP = (p.subtract(BigInteger.ONE)).divide(BigInteger.TWO);
        }
        while (!isPrime(p, 100) || !isPrime(safeP, 100));
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
        return !fastExpo(q, expo, p).equals(BigInteger.ONE);
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
    public boolean isPrime(BigInteger n, int loop) {
        for (int i = 0; i < loop; i++) {
            BigInteger randomNum = randomBigInt(BigInteger.TWO, n.subtract(BigInteger.ONE));
            BigInteger expo = n.subtract(BigInteger.ONE).divide(BigInteger.TWO);
            BigInteger p = fastExpo(randomNum, expo, n);
            if (!p.equals(BigInteger.ONE) && !p.equals(n.subtract(BigInteger.ONE)))
                return false;
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
            base = base.pow(2).mod(p);
            if (binary[i] == '1'){
                res = res.multiply(base).mod(p);
            }
        }
        return res;
    }


}
