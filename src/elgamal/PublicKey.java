package elgamal;

import java.math.BigInteger;

public class PublicKey implements Key{
    private BigInteger p;
    private BigInteger q;
    private BigInteger y;

    public PublicKey(BigInteger p, BigInteger q, BigInteger y) {
        this.p = p;
        this.q = q;
        this.y = y;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }

    public BigInteger getY() {
        return y;
    }

    public void setY(BigInteger y) {
        this.y = y;
    }
}
