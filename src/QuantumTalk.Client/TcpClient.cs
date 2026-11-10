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

            Console.WriteLine("\n[READY] Type a message, or type '/file <path>' to transmit a file (Ctrl+C to exit):");
            while (true)
            {
                Console.Write("> ");
                string input = Console.ReadLine();
                if (string.IsNullOrEmpty(input)) continue;

                // Check if user is issuing the secure file upload command
                if (input.StartsWith("/file "))
                {
                    string filePath = input.Substring(6).Trim();
                    SendFileSecurely(filePath, stream, aesKey);
                }
                else
                {
                    // Treat as standard chat/code message string
                    // Prefixed with an indicator '0' byte so the server knows it's pure text
                    byte[] plainTextBytes = Encoding.UTF8.GetBytes(input);
                    byte[] textPayload = new byte[1 + plainTextBytes.Length];
                    textPayload[0] = 0; // Type 0 = Text Message
                    Array.Copy(plainTextBytes, 0, textPayload, 1, plainTextBytes.Length);

                    byte[] encryptedPayload = EncryptBytes(textPayload, aesKey);

                    // Transmit length header followed by encrypted payload block
                    byte[] lengthBuffer = BitConverter.GetBytes(encryptedPayload.Length);
                    stream.Write(lengthBuffer, 0, 4);
                    stream.Write(encryptedPayload, 0, encryptedPayload.Length);
                    stream.Flush();
                }
            }
        }

        private static void SendFileSecurely(string filePath, NetworkStream stream, byte[] aesKey)
        {
            if (!File.Exists(filePath))
            {
                Console.WriteLine("[ERROR] Specified file target does not exist locally.");
                return;
            }

            try
            {
                string fileName = Path.GetFileName(filePath);
                byte[] fileNameBytes = Encoding.UTF8.GetBytes(fileName);
                byte[] fileDataBytes = File.ReadAllBytes(filePath);

                // Build Packet Structure: [Type Byte (1=File)] + [Name Length (4B)] + [Filename] + [Content Payload]
                byte[] unencryptedPayload = new byte[1 + 4 + fileNameBytes.Length + fileDataBytes.Length];
                unencryptedPayload[0] = 1; // Type 1 = File Transfer
                Array.Copy(BitConverter.GetBytes(fileNameBytes.Length), 0, unencryptedPayload, 1, 4);
                Array.Copy(fileNameBytes, 0, unencryptedPayload, 5, fileNameBytes.Length);
                Array.Copy(fileDataBytes, 0, unencryptedPayload, 5 + fileNameBytes.Length, fileDataBytes.Length);

                // Quantum-safe AES-GCM encryption envelope
                byte[] encryptedPayload = EncryptBytes(unencryptedPayload, aesKey);

                // Send sizing indicator block then pipeline the transaction data
                byte[] lengthBuffer = BitConverter.GetBytes(encryptedPayload.Length);
                stream.Write(lengthBuffer, 0, 4);
                stream.Write(encryptedPayload, 0, encryptedPayload.Length);
                stream.Flush();

                Console.WriteLine($"[MACBOOK] Securely dispatched: '{fileName}' ({fileDataBytes.Length} bytes).");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Failed to compile and ship file: {ex.Message}");
            }
        }

        private static byte[] EncryptBytes(byte[] plainBytes, byte[] key)
        {
            byte[] nonce = new byte[12];
            RandomNumberGenerator.Fill(nonce);
            byte[] tag = new byte[16];
            byte[] ciphertext = new byte[plainBytes.Length];

            using AesGcm aesGcm = new AesGcm(key, 16);
            aesGcm.Encrypt(nonce, plainBytes, ciphertext, tag);

            // Output format payload envelope matching Server parsing expectations
            byte[] payload = new byte[12 + 16 + ciphertext.Length];
            Array.Copy(nonce, 0, payload, 0, 12);
            Array.Copy(tag, 0, payload, 12, 16);
            Array.Copy(ciphertext, 0, payload, 28, ciphertext.Length);

            return payload;
        }
    }
}
