using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using QuantumCryptography.Shared;

namespace QuantumCryptography.Client
{
    class Program
    {
        static async Task Main(string[] args)
        {
            string serverIp = "127.0.0.1"; // Change to your external home IP for remote work
            int port = 8080;

            Console.WriteLine($"[MACBOOK] Connecting to server at {serverIp}:{port}...");
            using TcpClient client = new TcpClient(serverIp, port);
            using NetworkStream stream = client.GetStream();

            // 1. Quantum Key Handshake
            MlKemParameters mlKemParams = MlKemParameters.ml_kem_768;
            byte[] publicKeyBuffer = new byte[1184];
            int bytesRead = stream.Read(publicKeyBuffer, 0, publicKeyBuffer.Length);

            MlKemPublicKeyParameters serverPublicKey = MlKemPublicKeyParameters.FromEncoding(mlKemParams, publicKeyBuffer);
            SecureRandom random = new SecureRandom();
            MlKemGenerator macbookGenerator = new MlKemGenerator(random);
            
            ISecretWithEncapsulation secretResult = macbookGenerator.GenerateEncapsulated(serverPublicKey);
            byte[] sharedSecret = secretResult.GetSecret();
            byte[] encryptedCiphertext = secretResult.GetEncapsulation();

            stream.Write(encryptedCiphertext, 0, encryptedCiphertext.Length);
            stream.Flush();
            Console.WriteLine("[MACBOOK] Quantum Handshake Established.");

            byte[] aesKey = new byte[32];
            Array.Copy(sharedSecret, aesKey, 32);

            // 2. Start BIDIRECTIONAL Listening Thread
            _ = Task.Run(() => StartListeningBackground(stream, aesKey));

            // 3. User Input Loop
            Console.WriteLine("\n[SECURE CHANNEL OPEN] Type text, or '/file <path>' to stream a large file:");
            while (true)
            {
                string input = Console.ReadLine();
                if (string.IsNullOrEmpty(input)) continue;

                if (input.StartsWith("/file "))
                {
                    string filePath = input.Substring(6).Trim();
                    await StreamFileInChunksAsync(filePath, stream, aesKey);
                }
                else
                {
                    // Type 0 = Text Message
                    byte[] plainTextBytes = Encoding.UTF8.GetBytes(input);
                    byte[] textPayload = new byte[1 + plainTextBytes.Length];
                    textPayload[0] = 0; 
                    Array.Copy(plainTextBytes, 0, textPayload, 1, plainTextBytes.Length);

                    byte[] encryptedPayload = QuantumCrypto.EncryptBytes(textPayload, aesKey);
                    SendRawPayload(stream, encryptedPayload);
                }
            }
        }

        private static void StartListeningBackground(NetworkStream stream, byte[] aesKey)
        {
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

                    if (payloadType == 0) // Text message received from Server
                    {
                        string message = Encoding.UTF8.GetString(decryptedBytes, 1, decryptedBytes.Length - 1);
                        Console.WriteLine($"\n[SERVER]: {message}\n> ");
                    }
                }
            }
            catch { Console.WriteLine("\n[MACBOOK] Connection to server lost."); }
        }

        private static async Task StreamFileInChunksAsync(string filePath, NetworkStream stream, byte[] aesKey)
        {
            if (!File.Exists(filePath))
            {
                Console.WriteLine("[ERROR] File target does not exist.");
                return;
            }

            try
            {
                string fileName = Path.GetFileName(filePath);
                byte[] fileNameBytes = Encoding.UTF8.GetBytes(fileName);
                
                // Signal File Start: Type 1 = File Metadata
                byte[] metaPayload = new byte[1 + 4 + fileNameBytes.Length];
                metaPayload[0] = 1;
                Array.Copy(BitConverter.GetBytes(fileNameBytes.Length), 0, metaPayload, 1, 4);
                Array.Copy(fileNameBytes, 0, metaPayload, 5, fileNameBytes.Length);
                SendRawPayload(stream, QuantumCrypto.EncryptBytes(metaPayload, aesKey));

                // Stream Content in Chunks (64KB chunks to remain memory efficient)
                using FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                byte[] buffer = new byte[64 * 1024]; 
                int bytesRead;

                Console.WriteLine($"[STREAMING] Pipelining '{fileName}' to home computer...");
                while ((bytesRead = await fs.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    // Type 2 = File Chunk Content
                    byte[] chunkPayload = new byte[1 + 4 + bytesRead];
                    chunkPayload[0] = 2; // Chunk type indicator
                    Array.Copy(BitConverter.GetBytes(bytesRead), 0, chunkPayload, 1, 4);
                    Array.Copy(buffer, 0, chunkPayload, 5, bytesRead);

                    SendRawPayload(stream, QuantumCrypto.EncryptBytes(chunkPayload, aesKey));
                }

                // Signal File End: Type 3 = End of File marker
                byte[] endPayload = new byte[] { 3 };
                SendRawPayload(stream, QuantumCrypto.EncryptBytes(endPayload, aesKey));
                Console.WriteLine($"[SUCCESS] Finished streaming '{fileName}'.");
            }
            catch (Exception ex) { Console.WriteLine($"[ERROR] Stream failed: {ex.Message}"); }
        }

        private static void SendRawPayload(NetworkStream stream, byte[] payload)
        {
            byte[] lengthBuffer = BitConverter.GetBytes(payload.Length);
            stream.Write(lengthBuffer, 0, 4);
            stream.Write(payload, 0, payload.Length);
            stream.Flush();
        }
    }
}