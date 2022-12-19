/*
 * Author: John Dunbar
 * License: UNLICENSED
 * 
 * Theory on RSA provided in 'Discrete Mathematics and its Applications' by Kenneth Rosen.
 * 
 * Whilst this code does utilise RSA encoding and decoding, further security measures should
 * be taken to ensure encrypted data's safety. As such, this code accepts no liability for
 * integrity breaches if used improperly in accordance with UNLICENSED standards (cited below)
 * and should be used in conjunction with other security measures to maintain data integrity.
 * 
"""
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>
"""
 */

import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;

public class RSA {
    private BigInteger p;
    private BigInteger q;
    private BigInteger n;
    private BigInteger m;
    private BigInteger e;
    private BigInteger d;
    private int bitlength = 64; // most effective is 1024
    private Random r;

    public RSA() {
        r = new Random();
        p = BigInteger.probablePrime(bitlength, r);
        q = BigInteger.probablePrime(bitlength, r);
        n = p.multiply(q);
        m = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        e = BigInteger.probablePrime(bitlength / 2, r);
        
        while (m.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(m) < 0) {
            e.add(BigInteger.ONE);
        }
        d = e.modInverse(m);
    }

    private BigInteger encrypt(BigInteger message) {
        return message.modPow(e, n);
    }

    private BigInteger decrypt(BigInteger message) {
        return message.modPow(d, n);
    }

    public static void main(String[] args) {

        RSA rsa = new RSA();

        try (Scanner input = new Scanner(System.in)) {
            System.out.println("Enter a message to be encrypted using RSA:");
            String teststring = input.nextLine();

            System.out.println("-------- Plaintext Message --------\n");
            System.out.println("Plaintext: " + teststring+"\n");

            BigInteger plaintext = new BigInteger(teststring.getBytes());
            BigInteger ciphertext = rsa.encrypt(plaintext);

            System.out.println("-------- Ciphertext Message --------\n");
            System.out.println("Ciphertext: " + ciphertext+"\n");

            BigInteger decryptedtext = rsa.decrypt(ciphertext);

            System.out.println("-------- Decrypted Message --------\n");
            System.out.println("Decrypted: " + new String(decryptedtext.toByteArray())+"\n");

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Fatal error");
        }
    }
}