using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using QuantumCryptography.Shared; // Hent det fælles bibliotek

namespace QuantumCryptography.Server
{
    class Program
    {
        static void Main(string[] args)
        {
            int port = 8080;
            TcpListener listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            Console.WriteLine($"[SERVER] Lytter efter MacBook på port {port}...");

            using TcpClient client = listener.AcceptTcpClient();
            using NetworkStream stream = client.GetStream();
            Console.WriteLine("[SERVER] MacBook forbundet! Starter kvante-håndtryk...");

            // 1. Generer kvantesikre nøgler (ML-KEM-768)
            SecureRandom random = new SecureRandom();
            MlKemParameters mlKemParams = MlKemParameters.ml_kem_768;
            MlKemKeyPairGenerator keyGen = new MlKemKeyPairGenerator();
            keyGen.Init(new MlKemKeyGenerationParameters(random, mlKemParams));
            
            AsymmetricCipherKeyPair serverKeyPair = keyGen.GenerateKeyPair();
            MlKemPublicKeyParameters serverPublicKey = (MlKemPublicKeyParameters)serverKeyPair.Public;
            MlKemPrivateKeyParameters serverPrivateKey = (MlKemPrivateKeyParameters)serverKeyPair.Private;

            // 2. Send Public Key afsted
            byte[] serializedPublicKey = serverPublicKey.GetEncoded();
            stream.Write(serializedPublicKey, 0, serializedPublicKey.Length);
            stream.Flush();

            // 3. Hent den krypterede session-pakke retur
            byte[] encryptedCiphertext = new byte[1088];
            int bytesRead = stream.Read(encryptedCiphertext, 0, encryptedCiphertext.Length);

            // 4. Udpak den delte krypteringsnøgle
            MlKemExtractor serverExtractor = new MlKemExtractor(serverPrivateKey);
            byte[] sharedSecret = serverExtractor.ExtractSecret(encryptedCiphertext);
            Console.WriteLine("[SERVER] Kvantesikkert håndtryk godkendt. Kanalen er låst.");

            byte[] aesKey = new byte[32];
            Array.Copy(sharedSecret, aesKey, 32);

            try
            {
                while (true)
                {
                    byte[] lengthBuffer = new byte[4];
                    if (stream.Read(lengthBuffer, 0, 4) == 0) break;
                    int cipherLength = BitConverter.ToInt32(lengthBuffer, 0);

                    byte[] encryptedPayload = new byte[cipherLength];
                    int totalRead = 0;
                    while (totalRead < cipherLength)
                    {
                        int read = stream.Read(encryptedPayload, totalRead, cipherLength - totalRead);
                        if (read == 0) throw new Exception("Forbindelsen blev afbrudt midt i en overførsel.");
                        totalRead += read;
                    }

                    // Kald den fælles dekrypteringsmetode fra Shared-projektet
                    byte[] decryptedBytes = QuantumCrypto.DecryptBytes(encryptedPayload, aesKey);
                    byte payloadType = decryptedBytes[0];

                    if (payloadType == 0)
                    {
                        // Behandl Type 0: Tekst / Kildekodebesked
                        string message = Encoding.UTF8.GetString(decryptedBytes, 1, decryptedBytes.Length - 1);
                        Console.WriteLine($"\n[MODTAGET KODE/BESKED]:\n{message}");
                    }
                    else if (payloadType == 1)
                    {
                        // Behandl Type 1: Fil
                        int fileNameLength = BitConverter.ToInt32(decryptedBytes, 1);
                        string fileName = Encoding.UTF8.GetString(decryptedBytes, 5, fileNameLength);

                        int fileDataOffset = 5 + fileNameLength;
                        int fileDataLength = decryptedBytes.Length - fileDataOffset;
                        byte[] fileData = new byte[fileDataLength];
                        Array.Copy(decryptedBytes, fileDataOffset, fileData, 0, fileDataLength);

                        // Opret en sikker mappe på computeren og gem filen
                        string saveDirectory = Path.Combine(Environment.CurrentDirectory, "ReceivedFiles");
                        Directory.CreateDirectory(saveDirectory);
                        string savePath = Path.Combine(saveDirectory, fileName);
                        File.WriteAllBytes(savePath, fileData);

                        Console.WriteLine($"\n[MODTAGET FIL GEMT]: '{fileName}' ({fileDataLength} bytes).");
                        Console.WriteLine($"Sti: {savePath}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SERVER] Forbindelse lukket: {ex.Message}");
            }
        }
    }
}
