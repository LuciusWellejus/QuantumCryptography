using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using QuantumCryptography.Shared;

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
            Console.WriteLine("[SERVER] MacBook linked! Initiating Quantum Handshake...");

            // 1. Quantum Handshake Setup
            SecureRandom random = new SecureRandom();
            MlKemParameters mlKemParams = MlKemParameters.ml_kem_768;
            MlKemKeyPairGenerator keyGen = new MlKemKeyPairGenerator();
            keyGen.Init(new MlKemKeyGenerationParameters(random, mlKemParams));
            
            AsymmetricCipherKeyPair serverKeyPair = keyGen.GenerateKeyPair();
            MlKemPublicKeyParameters serverPublicKey = (MlKemPublicKeyParameters)serverKeyPair.Public;
            MlKemPrivateKeyParameters serverPrivateKey = (MlKemPrivateKeyParameters)serverKeyPair.Private;

            byte[] serializedPublicKey = serverPublicKey.GetEncoded();
            stream.Write(serializedPublicKey, 0, serializedPublicKey.Length);
            stream.Flush();

            byte[] encryptedCiphertext = new byte[1088];
            stream.Read(encryptedCiphertext, 0, encryptedCiphertext.Length);

            MlKemExtractor serverExtractor = new MlKemExtractor(serverPrivateKey);
            byte[] sharedSecret = serverExtractor.ExtractSecret(encryptedCiphertext);
            Console.WriteLine("[SERVER] Handshake Certified. Channel encrypted.");

            byte[] aesKey = new byte[32];
            Array.Copy(sharedSecret, aesKey, 32);

            // 2. Start Background Reader Thread for Multi-Type Streams
            _ = Task.Run(() => StartListeningBackground(stream, aesKey));

            // 3. Bidirectional Write Prompt
            Console.WriteLine("\n[SECURE CHANNEL OPEN] Type text to send back to MacBook anytime:");
            while (true)
            {
                string response = Console.ReadLine();
                if (string.IsNullOrEmpty(response)) continue;

                // Type 0 = Text Message
                byte[] plainBytes = Encoding.UTF8.GetBytes(response);
                byte[] textPayload = new byte[1 + plainBytes.Length];
                textPayload[0] = 0;
                Array.Copy(plainBytes, 0, textPayload, 1, plainBytes.Length);

                byte[] encryptedPayload = QuantumCrypto.EncryptBytes(textPayload, aesKey);
                byte[] lengthBuffer = BitConverter.GetBytes(encryptedPayload.Length);
                stream.Write(lengthBuffer, 0, 4);
                stream.Write(encryptedPayload, 0, encryptedPayload.Length);
                stream.Flush();
            }
        }

        private static void StartListeningBackground(NetworkStream stream, byte[] aesKey)
        {
            FileStream activeFileStream = null;
            string currentFileName = "";

            try
            {
                byte[] lengthBuffer = new byte[4];
                while (stream.Read(lengthBuffer, 0, 4) > 0)
                {
                    int cipherLength = BitConverter.ToInt32(lengthBuffer, 0);
                    byte[] encryptedPayload = new byte[cipherLength];
                    int totalRead = 0;
                    while (totalRead < cipherLength)
                    {
                        int read = stream.Read(encryptedPayload, totalRead, cipherLength - totalRead);
                        if (read == 0) return;
                        totalRead += read;
                    }

                    byte[] decryptedBytes = QuantumCrypto.DecryptBytes(encryptedPayload, aesKey);
                    byte payloadType = decryptedBytes[0];

                    if (payloadType == 0) // Chat message
                    {
                        string message = Encoding.UTF8.GetString(decryptedBytes, 1, decryptedBytes.Length - 1);
                        Console.WriteLine($"\n[MACBOOK]: {message}\n> ");
                    }
                    else if (payloadType == 1) // File Transfer Start Metadata
                    {
                        int nameLength = BitConverter.ToInt32(decryptedBytes, 1);
                        currentFileName = Encoding.UTF8.GetString(decryptedBytes, 5, nameLength);
                        
                        string saveFolder = Path.Combine(Environment.CurrentDirectory, "ReceivedFiles");
                        Directory.CreateDirectory(saveFolder);
                        string fullPath = Path.Combine(saveFolder, currentFileName);

                        activeFileStream = new FileStream(fullPath, FileMode.Create, FileAccess.Write);
                        Console.WriteLine($"\n[INCOMING FILE] Streaming '{currentFileName}' to disk chunk-by-chunk...");
                    }
                    else if (payloadType == 2 && activeFileStream != null) // File Chunk Data
                    {
                        int chunkDataLength = BitConverter.ToInt32(decryptedBytes, 1);
                        activeFileStream.Write(decryptedBytes, 5, chunkDataLength);
                    }
                    else if (payloadType == 3 && activeFileStream != null) // End of File
                    {
                        activeFileStream.Flush();
                        activeFileStream.Close();
                        activeFileStream.Dispose();
                        activeFileStream = null;
                        Console.WriteLine($"\n[COMPLETED] '{currentFileName}' successfully assembled and saved.\n> ");
                    }
                }
            }
            catch (Exception ex)
            {
                activeFileStream?.Close();
                Console.WriteLine($"\n[SERVER] Connection broken: {ex.Message}");
            }
        }
    }
}