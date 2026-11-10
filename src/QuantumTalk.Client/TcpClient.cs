using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace QuantumCryptography.Client
{
    class Program
    {
        static void Main(string[] args)
        {
            // Replace "127.0.0.1" with your home server's public IP address when testing remotely
            string serverIp = "127.0.0.1"; 
            int port = 8080;

            Console.WriteLine($"[MACBOOK] Connecting to server at {serverIp}:{port}...");
            using TcpClient client = new TcpClient(serverIp, port);
            using NetworkStream stream = client.GetStream();

            // 1. Receive the server's Quantum Public Key
            MlKemParameters mlKemParams = MlKemParameters.ml_kem_768;
            byte[] publicKeyBuffer = new byte[1184]; // Fixed size for ML-KEM-768 public keys
            int bytesRead = stream.Read(publicKeyBuffer, 0, publicKeyBuffer.Length);

            // 2. Process key and encapsulate our transmission secret
            MlKemPublicKeyParameters serverPublicKey = MlKemPublicKeyParameters.FromEncoding(mlKemParams, publicKeyBuffer);
            SecureRandom random = new SecureRandom();
            MlKemGenerator macbookGenerator = new MlKemGenerator(random);
            
            ISecretWithEncapsulation secretResult = macbookGenerator.GenerateEncapsulated(serverPublicKey);
            byte[] sharedSecret = secretResult.GetSecret();
            byte[] encryptedCiphertext = secretResult.GetEncapsulation();

            // 3. Send the encrypted key package back to the server
            stream.Write(encryptedCiphertext, 0, encryptedCiphertext.Length);
            stream.Flush();
            Console.WriteLine("[MACBOOK] Quantum Handshake Established.");

            // 4. Enter Safe Messaging Loop
            byte[] aesKey = new byte[32];
            Array.Copy(sharedSecret, aesKey, 32);

            Console.WriteLine("Type your messages or code below (Press Ctrl+C to exit):");
            while (true)
            {
                Console.Write("> ");
                string message = Console.ReadLine();
                if (string.IsNullOrEmpty(message)) continue;

                // Encrypt payload using AES-GCM
                byte[] encryptedPayload = EncryptMessage(message, aesKey);

                // Write the size of payload first, followed by payload
                byte[] lengthBuffer = BitConverter.GetBytes(encryptedPayload.Length);
                stream.Write(lengthBuffer, 0, 4);
                stream.Write(encryptedPayload, 0, encryptedPayload.Length);
                stream.Flush();
            }
        }

        private static byte[] EncryptMessage(string plainText, byte[] key)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] nonce = new byte[12];
            RandomNumberGenerator.Fill(nonce); // Generate a unique nonce per transmission
            byte[] tag = new byte[16];
            byte[] ciphertext = new byte[plainBytes.Length];

            using AesGcm aesGcm = new AesGcm(key, 16);
            aesGcm.Encrypt(nonce, plainBytes, ciphertext, tag);

            // Package it as: [ 12-byte Nonce ] [ 16-byte Tag ] [ Variable Ciphertext ]
            byte[] payload = new byte[12 + 16 + ciphertext.Length];
            Array.Copy(nonce, 0, payload, 0, 12);
            Array.Copy(tag, 0, payload, 12, 16);
            Array.Copy(ciphertext, 0, payload, 28, ciphertext.Length);

            return payload;
        }
    }
}
