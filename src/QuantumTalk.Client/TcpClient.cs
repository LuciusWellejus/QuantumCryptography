using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using QuantumCryptography.Shared; // Hent det fælles bibliotek

namespace QuantumCryptography.Client
{
    class Program
    {
        static void Main(string[] args)
        {
            string serverIp = "127.0.0.1"; // Skift til din eksterne hjemme-IP ved remote test
            int port = 8080;

            Console.WriteLine($"[MACBOOK] Forbinder til server på {serverIp}:{port}...");
            using TcpClient client = new TcpClient(serverIp, port);
            using NetworkStream stream = client.GetStream();

            // 1. Modtag serverens kvantesikre Public Key
            MlKemParameters mlKemParams = MlKemParameters.ml_kem_768;
            byte[] publicKeyBuffer = new byte[1184];
            int bytesRead = stream.Read(publicKeyBuffer, 0, publicKeyBuffer.Length);

            // 2. Processer nøglen og indkapsl krypteringsnøglen
            MlKemPublicKeyParameters serverPublicKey = MlKemPublicKeyParameters.FromEncoding(mlKemParams, publicKeyBuffer);
            SecureRandom random = new SecureRandom();
            MlKemGenerator macbookGenerator = new MlKemGenerator(random);
            
            ISecretWithEncapsulation secretResult = macbookGenerator.GenerateEncapsulated(serverPublicKey);
            byte[] sharedSecret = secretResult.GetSecret();
            byte[] encryptedCiphertext = secretResult.GetEncapsulation();

            // 3. Send den krypterede nøglepakke tilbage til serveren
            stream.Write(encryptedCiphertext, 0, encryptedCiphertext.Length);
            stream.Flush();
            Console.WriteLine("[MACBOOK] Kvantesikkert håndtryk etableret.");

            // 4. Klargør AES-256 nøglen baseret på kvante-nøglen
            byte[] aesKey = new byte[32];
            Array.Copy(sharedSecret, aesKey, 32);

            Console.WriteLine("\n[KLAR] Skriv tekst/kode, eller brug '/file [sti]' for at sende en fil:");
            while (true)
            {
                Console.Write("> ");
                string input = Console.ReadLine();
                if (string.IsNullOrEmpty(input)) continue;

                if (input.StartsWith("/file "))
                {
                    string filePath = input.Substring(6).Trim();
                    SendFileSecurely(filePath, stream, aesKey);
                }
                else
                {
                    // Pakke-type 0: Tekstbesked
                    byte[] plainTextBytes = Encoding.UTF8.GetBytes(input);
                    byte[] textPayload = new byte[1 + plainTextBytes.Length];
                    textPayload[0] = 0; 
                    Array.Copy(plainTextBytes, 0, textPayload, 1, plainTextBytes.Length);

                    // Kald den fælles krypteringsmetode
                    byte[] encryptedPayload = QuantumCrypto.EncryptBytes(textPayload, aesKey);

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
                Console.WriteLine("[FEJL] Den angivne fil eksisterer ikke lokalt.");
                return;
            }

            try
            {
                string fileName = Path.GetFileName(filePath);
                byte[] fileNameBytes = Encoding.UTF8.GetBytes(fileName);
                byte[] fileDataBytes = File.ReadAllBytes(filePath);

                // Pakke-type 1: Filoverførsel -> [Type (1B)] + [Navne-længde (4B)] + [Navn] + [Data]
                byte[] unencryptedPayload = new byte[1 + 4 + fileNameBytes.Length + fileDataBytes.Length];
                unencryptedPayload[0] = 1; 
                Array.Copy(BitConverter.GetBytes(fileNameBytes.Length), 0, unencryptedPayload, 1, 4);
                Array.Copy(fileNameBytes, 0, unencryptedPayload, 5, fileNameBytes.Length);
                Array.Copy(fileDataBytes, 0, unencryptedPayload, 5 + fileNameBytes.Length, fileDataBytes.Length);

                // Kald den fælles krypteringsmetode
                byte[] encryptedPayload = QuantumCrypto.EncryptBytes(unencryptedPayload, aesKey);

                byte[] lengthBuffer = BitConverter.GetBytes(encryptedPayload.Length);
                stream.Write(lengthBuffer, 0, 4);
                stream.Write(encryptedPayload, 0, encryptedPayload.Length);
                stream.Flush();

                Console.WriteLine($"[MACBOOK] Filen '{fileName}' ({fileDataBytes.Length} bytes) er afsendt sikkert.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FEJL] Kunne ikke sende filen: {ex.Message}");
            }
        }
    }
}
