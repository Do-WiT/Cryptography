package elgamal;

import java.math.BigInteger;

public class PrivateKey {

    private BigInteger u;

    public PrivateKey(BigInteger u) {
        this.u = u;
    }

    public BigInteger getU() {
        return u;
    }
}
