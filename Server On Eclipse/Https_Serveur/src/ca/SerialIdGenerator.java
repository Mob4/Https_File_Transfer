package ca;

import java.math.BigInteger;

class SerialIdGenerator {
    
    private static BigInteger counter = BigInteger.ONE;
    
    public static synchronized BigInteger generate() {
        counter = counter.add(BigInteger.ONE);
        return counter;
    }
}
