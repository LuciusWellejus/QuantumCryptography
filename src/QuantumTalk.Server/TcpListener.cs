using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace QuantumCryptography.Server
{
    class Program
    {
        static void Main(string[] args)
        {
            int port = 8080;
            TcpListener listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            Console.WriteLine($"[SERVER] Listening for MacBook on port {port}...");

            using TcpClient client = listener.AcceptTcpClient();
            using NetworkStream stream = client.GetStream();
            Console.WriteLine("[SERVER] MacBook connected! Starting quantum handshake...");

            // 1. Quantum Key Generation (ML-KEM-768)
            SecureRandom random = new SecureRandom();
            MlKemParameters mlKemParams = MlKemParameters.ml_kem_768;
            MlKemKeyPairGenerator keyGen = new MlKemKeyPairGenerator();
            keyGen.Init(new MlKemKeyGenerationParameters(random, mlKemParams));
            
            AsymmetricCipherKeyPair serverKeyPair = keyGen.GenerateKeyPair();
            MlKemPublicKeyParameters serverPublicKey = (MlKemPublicKeyParameters)serverKeyPair.Public;
            MlKemPrivateKeyParameters serverPrivateKey = (MlKemPrivateKeyParameters)serverKeyPair.Private;

            // 2. Send the Public Key to the MacBook
            byte[] serializedPublicKey = serverPublicKey.GetEncoded();
            stream.Write(serializedPublicKey, 0, serializedPublicKey.Length);
            stream.Flush();

            // 3. Receive the Encrypted Ciphertext package back from the MacBook
            byte[] encryptedCiphertext = new byte[1088]; // Fixed size for ML-KEM-768 ciphertext
            int bytesRead = stream.Read(encryptedCiphertext, 0, encryptedCiphertext.Length);

            // 4. Extract the Shared Master Secret Key
            MlKemExtractor serverExtractor = new MlKemExtractor(serverPrivateKey);
            byte[] sharedSecret = serverExtractor.ExtractSecret(encryptedCiphertext);
            Console.WriteLine("[SERVER] Quantum Handshake Successful. Channel is secure.");

            // 5. Enter Safe Messaging Loop
            byte[] aesKey = new byte[32];
            Array.Copy(sharedSecret, aesKey, 32);

            try
            {
                while (true)
                {
                    // Read encrypted incoming message length header
                    byte[] lengthBuffer = new byte[4];
                    if (stream.Read(lengthBuffer, 0, 4) == 0) break;
                    int cipherLength = BitConverter.ToInt32(lengthBuffer, 0);

                    // Read the full payload package (Nonce + Ciphertext + Tag)
                    byte[] encryptedPayload = new byte[cipherLength];
                    int totalRead = 0;
                    while (totalRead < cipherLength)
                    {
                        int read = stream.Read(encryptedPayload, totalRead, cipherLength - totalRead);
                        if (read == 0) throw new Exception("Stream cut short during transaction.");
                        totalRead += read;
                    }

                    // Decrypt the raw payload back to unencrypted bytes
                    byte[] decryptedBytes = DecryptBytes(encryptedPayload, aesKey);

                    // Read the Type Byte marker (Index 0)
                    byte payloadType = decryptedBytes[0];

                    if (payloadType == 0)
                    {
                        // Handle Type 0: Pure Text / Source Code message
                        string message = Encoding.UTF8.GetString(decryptedBytes, 1, decryptedBytes.Length - 1);
                        Console.WriteLine($"\n[RECEIVED MSG/CODE]:\n{message}");
                    }
                    else if (payloadType == 1)
                    {
                        // Handle Type 1: Incoming File Stream
                        int fileNameLength = BitConverter.ToInt32(decryptedBytes, 1);
                        string fileName = Encoding.UTF8.GetString(decryptedBytes, 5, fileNameLength);

                        int fileDataOffset = 5 + fileNameLength;
                        int fileDataLength = decryptedBytes.Length - fileDataOffset;
                        byte[] fileData = new byte[fileDataLength];
                        Array.Copy(decryptedBytes, fileDataOffset, fileData, 0, fileDataLength);

                        // Save the file safely into a local directory
                        string saveDirectory = Path.Combine(Environment.CurrentDirectory, "ReceivedFiles");
                        Directory.CreateDirectory(saveDirectory);
                        string savePath = Path.Combine(saveDirectory, fileName);
                        File.WriteAllBytes(savePath, fileData);

                        Console.WriteLine($"\n[RECEIVED FILE]: '{fileName}' saved safely ({fileDataLength} bytes).");
                        Console.WriteLine($"Location: {savePath}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SERVER] Connection lost or closed: {ex.Message}");
            }
        }

        private static byte[] DecryptBytes(byte[] payload, byte[] key)
        {
            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];
            byte[] ciphertext = new byte[payload.Length - 28];

            Array.Copy(payload, 0, nonce, 0, 12);
            Array.Copy(payload, 12, tag, 0, 16);
            Array.Copy(payload, 28, ciphertext, 0, ciphertext.Length);

            byte[] decryptedBytes = new byte[ciphertext.Length];
            using AesGcm aesGcm = new AesGcm(key, 16);
            aesGcm.Decrypt(nonce, ciphertext, tag, decryptedBytes);

            return decryptedBytes;
        }
    }
}
