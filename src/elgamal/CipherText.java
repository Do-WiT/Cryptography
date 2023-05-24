package elgamal;

import java.math.BigInteger;

public class CipherText {
    private BigInteger a;
    private BigInteger b;

    public BigInteger getA() {
        return a;
    }

    public void setA(BigInteger a) {
        this.a = a;
    }

    public BigInteger getB() {
        return b;
    }

    public void setB(BigInteger b) {
        this.b = b;
    }
}
