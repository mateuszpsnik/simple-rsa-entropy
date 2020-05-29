using System;
using System.Collections.Generic;
using System.Text;
using System.Numerics;
using System.Diagnostics;

namespace SimpleRSA
{
    class EncryptionException : Exception
    {
        public EncryptionException(string? message) : base(message){}
    }

    class RSA
    {
        public RSA()
        {
            keyGenerated = false;
            messageEncrypted = false;
            entropy = 0.0;
        }

        RandomPrimeNumber randomPrime = new RandomPrimeNumber();

        BigInteger ciphertext;
        Dictionary<byte, int> byteOccurrence = new Dictionary<byte, int>();
        Dictionary<byte, double> byteProbability = new Dictionary<byte, double>();
        double entropy;
        BigInteger p;
        BigInteger q;
        BigInteger n;
        BigInteger phi;
        readonly BigInteger e = 65537; //the most commonly chosen e value, according to Wikipedia
        BigInteger d;

        bool keyGenerated;
        public event EventHandler KeyGenerated;

        bool messageEncrypted;
        public event EventHandler MessageEncrypted;


        public BigInteger Ciphertext => ciphertext;
        public Dictionary<byte, int> ByteOccurrence => byteOccurrence;
        public Dictionary<byte, double> ByteProbability => byteProbability;
        public double Entropy => entropy;

        /*
         The key for the RSA encryption is generates in the following way:
         1. We choose two big random prime numbers p and q. They are kept secret.
         2. Then n = p * q is computed - this is used as the modulus for both the public and private key.
         3. Next the Euler totient function is calculated - phi(n) = (p - 1)(q - 1). This is kept secret.
         4. In this step, we have to choose an integer e such that 1 < e < phi(n) and the greatest
            common divisor of e and phi(n) is 1.
         5. Next we need to find d which is the modular multiplicative inverse of e modulo phi(n).
            d is kept secret

            The pair (n, e) is the public key while d is the private key.
          */
        public void GenerateKey()
        {
            //according to Wikipedia, p and q should be chosen at random, 
            //and should be similar in magnitude but differ in length by a few digits 
            //to make factoring harder
            p = randomPrime.Generate(129);
            Debug.WriteLine($"p = {p}"); //writes p to output window so that we can check, if everything is ok
            q = randomPrime.Generate(128);
            Debug.WriteLine($"q = {q}");
            n = p * q;
            Debug.WriteLine($"n = {n}");
            phi = (p - 1) * (q - 1);
            Debug.WriteLine($"phi = {phi}");

            if (BigInteger.GreatestCommonDivisor(e, phi) == 1)
            {
                d = inverse(e, phi);
                Debug.WriteLine($"d = {d}");
                keyGenerated = true;
                OnKeyGenerated(EventArgs.Empty);
            }

            //In the future I will try to make these calculations asynchronously
        }


        public void Encrypt(string inputText)
        {
            byte[] inputTextAsBytes;

            //convert text to byte array
            inputTextAsBytes = Encoding.ASCII.GetBytes(inputText);
            
            if (!keyGenerated)
                throw new EncryptionException("Key was not generated");

            //covert message from bytes to a number
            BigInteger message = new BigInteger(inputTextAsBytes);

            if (message >= n)
                throw new EncryptionException("The message is too long");

            //c = m^e (mod n)
            ciphertext = BigInteger.ModPow(message, e, n);
            messageEncrypted = true;
            OnMessageEncrypted(EventArgs.Empty);
        }

        public void CountStatisticsAndEntropy(BigInteger ciphertext)
        {
            if (!messageEncrypted)
                throw new EncryptionException("You did not encrypt any message");

            byte[] encryptedAsByteArray = ciphertext.ToByteArray(); // from number to array of bytes

            byte[] countOccurrances = new byte[byte.MaxValue + 1];

            foreach (byte b in encryptedAsByteArray) // counting how many times each byte occurred in the ciphertext
                countOccurrances[b]++;

            int numberOfBytes = encryptedAsByteArray.Length;
            for (int i = 0; i <= byte.MaxValue; i++)
            {
                int value = countOccurrances[i];
                if (value != 0)
                {
                    byteOccurrence.Add(Convert.ToByte(i), value); // updates dictionary of bytes and number of each of them in the ciphertext
                    double probability = (double)value / numberOfBytes;
                    byteProbability.Add(Convert.ToByte(i), probability);
                }
            }
               
            // entropy is counted here
            foreach (double probability in byteProbability.Values)
            {
                double term = -probability * Math.Log2(probability); 
                entropy += term;
            }
        }

        /*
         This method finds modular multiplicative inverse of the number 'a' under modulo 'm'.
         It implements the extended Euclidean algorithm.
         This implementation is based on implementations from this website:
         https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
         */
        private BigInteger inverse(BigInteger a, BigInteger m)
        {
            BigInteger m0 = m;
            BigInteger y = 0, x = 1;

            while (a > 1)
            {
                BigInteger q = a / m;
                BigInteger t = m;

                m = a % m;
                a = t;
                t = y;

                y = x - q * y;
                x = t;
            }

            if (x < 0)
                x += m0;

            return x;
        }


        //Methods used to invoke KeyGenerated and MessageEncrypted events 
        protected virtual void OnKeyGenerated(EventArgs e)
        {
            KeyGenerated?.Invoke(this, e);
        }

        protected virtual void OnMessageEncrypted(EventArgs e)
        {
            MessageEncrypted?.Invoke(this, e);
        }
    }
}
