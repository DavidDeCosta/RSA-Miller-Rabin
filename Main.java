//Name: David DeCosta
/*
 * Description: This program simulates RSA encryption and decryption processes using randomly 
 * generated prime numbers and modular arithmetic, and demonstrates the generation of secure 10-digit 
 * prime numbers using probabilistic primality testing methods.
 */

 import java.math.BigInteger;
 import java.util.Random;

 public class Main {
    public static final Random rand = new Random(); 

    public static void main(String[] args) {
        
        //Question 1
         BigInteger message1 = new BigInteger("88");
         BigInteger e1 = new BigInteger("7");
         BigInteger p1 = new BigInteger("17");
         BigInteger q1 = new BigInteger("11");
         testRSA(message1, e1, p1, q1);

         BigInteger message2 = new BigInteger("1070777");
         BigInteger e2 = new BigInteger("948047");
         BigInteger p2 = new BigInteger("1223");
         BigInteger q2 = new BigInteger("1987");
         testRSA(message2, e2, p2, q2);

         //Question 2
         BigInteger primeNumber = getTenDigitPrime();
         System.out.println("Random 10 digit prime number: " + primeNumber);

    }

    public static void testRSA(BigInteger message, BigInteger e, BigInteger p, BigInteger q) {

        BigInteger n = p.multiply(q);   //(n = p*q)
        BigInteger x = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)); // (p-1)(q-1)) private key
        BigInteger d = e.modInverse(x); // inverse of e mod (n)
        BigInteger encrypted = message.modPow(e, n);      // encrypt using public key e and mod n
        BigInteger decrypted = encrypted.modPow(d, n);    // decrupt using the private key d and mod n

        System.out.println("Orig msg: " + message);
        System.out.println("Encrypt msg: " + encrypted);
        System.out.println("Decryp msg: " + decrypted);
        System.out.println("Public key: " + e);
        System.out.println("Private key: " + d + "\n");
    }

    public static BigInteger getTenDigitPrime() {
        BigInteger min = BigInteger.TEN.pow(9); // smallest 10-digit number which is 1 followed by 9 zeross
        BigInteger max = BigInteger.TEN.pow(10).subtract(BigInteger.ONE); // largest 10-digit number all 9s

        while (true) { //just keep checking
            BigInteger primeNumber = getRandomNum(min, max).nextProbablePrime(); //random start point then find a maybe prime
            if (primeNumber.compareTo(max) <= 0 && isPrime(primeNumber, 7)) { // make sure in range then send to check if prime
                return primeNumber; 
            }
        }
    }

    public static boolean isPrime(BigInteger primeNumber, int numOfLoops) {

        if (primeNumber.compareTo(BigInteger.TWO) < 0){ //numbers less then 2 not prime
            return false;
        } 
        if (primeNumber.compareTo(BigInteger.TWO) == 0){ //2 is the smallest prime number
            return true;
        }
        if (primeNumber.mod(BigInteger.TWO).equals(BigInteger.ZERO)){ //if its divisible by 2 its not prime
            return false;
        }

        BigInteger d = primeNumber.subtract(BigInteger.ONE);
        while (d.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            d = d.divide(BigInteger.TWO);  //keep dividing by 2 until its odd
        }

        for (int i = 0; i < numOfLoops; i++) {
            if (!millerRabinPrimTest(primeNumber, d)) { //if it fails return false
                return false;
            }
        }
        return true;
    }

    public static boolean millerRabinPrimTest(BigInteger primeNumber, BigInteger d) {
        BigInteger a = getRandomNum(BigInteger.TWO, primeNumber.subtract(BigInteger.TWO)); // find a witness num between 2 and primeNumber - 2
        BigInteger x = a.modPow(d, primeNumber); // a^d mod n

        if (x.equals(BigInteger.ONE) || x.equals(primeNumber.subtract(BigInteger.ONE))) { //if x is 1 or equal to primeNumber - 1 its prime
            return true;
        }

        while (!x.equals(primeNumber.subtract(BigInteger.ONE))) {
            x = x.modPow(BigInteger.TWO, primeNumber);  //keep squaring x until it = to primeNumber - 1 or 1
            if (x.equals(BigInteger.ONE)) {  //if x is 1 its not prime
                return false; 
            }
        }
        return true;  //it can be prime
    }


    public static BigInteger getRandomNum(BigInteger min, BigInteger max) {
        BigInteger betweenMinAndMax = max.subtract(min);
        betweenMinAndMax = betweenMinAndMax.add(BigInteger.ONE);
        BigInteger randomBigInt = new BigInteger(max.bitLength(), rand); //makes sure same length as max
        BigInteger result = randomBigInt.mod(betweenMinAndMax).add(min); //random number between min and max
    
        return result; 
    }
    
}