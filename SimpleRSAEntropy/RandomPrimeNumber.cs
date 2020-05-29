using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Numerics;

namespace SimpleRSA
{
    class RandomPrimeNumber
    {
        public BigInteger Generate(int numberOfBytes)
        {
            BigInteger number;
            do
            {
                number = new BigInteger(randomByteArray(numberOfBytes));
            } while (!test(number));
            
            return number;
        }

        private static byte[] randomByteArray(int numberOfBytes)
        {
            using(RNGCryptoServiceProvider rngCSP = new RNGCryptoServiceProvider())
            {
                byte[] array = new byte[numberOfBytes];

                //fills the array with random bytes
                rngCSP.GetBytes(array);

                //append zero to the end of the array in order to get only positive numbers
                //BigInteger constructor reads an array from the end
                List<byte> bytesList = new List<byte>(array);
                byte zero = 0;
                bytesList.Add(zero);
                array = bytesList.ToArray();

                //set first byte to 1 so that the last digit of a BigInteger will be 1
                //that easily excludes all numbers divisible by 2, 4, etc.
                array[0] = 1;

                return array;
            }
        }

        /*
         This is a very simple test based on Fermat's Little Theorem.
         If says that if a^n - a is divisible by n, then n is probably a prime number (1 <= a <= n).
         That means if (a^(n-1)) mod n == 1 then n is probably prime.
         If (a^(n-1)) mod n != 1 then n is not a prime number.

         Of course, some composite numbers might pass this test but as I will be using
         this generator is a simple implementation of the RSA algorithm which will NOT be 
         a part of some strong cryptographic system, I think that's enough. And therefore 
         I will be using only a few numbers as 'a'.
        */
        private bool test(BigInteger number)
        {
            for (int i = 2; i <= 4; i++)
            {
                if (BigInteger.ModPow(i, number - 1, number) != 1)
                    return false;
            }
            return true;
        }
    }
}
