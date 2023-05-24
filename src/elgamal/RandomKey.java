package elgamal;

import java.math.BigInteger;

public class RandomKey {
    private BigInteger randomKey;

    public RandomKey(BigInteger randomKey) {
        this.randomKey = randomKey;
    }

    public BigInteger getRandomKey() {
        return randomKey;
    }

}
