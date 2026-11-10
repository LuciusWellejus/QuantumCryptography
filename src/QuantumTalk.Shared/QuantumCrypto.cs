using System;
using System.Security.Cryptography;

namespace QuantumCryptography.Shared
{
    public static class QuantumCrypto
    {
        public static byte[] EncryptBytes(byte[] plainBytes, byte[] key)
        {
            byte[] nonce = new byte[12];
            RandomNumberGenerator.Fill(nonce);
            byte[] tag = new byte[16];
            byte[] ciphertext = new byte[plainBytes.Length];

            using AesGcm aesGcm = new AesGcm(key, 16);
            aesGcm.Encrypt(nonce, plainBytes, ciphertext, tag);

            byte[] payload = new byte[12 + 16 + ciphertext.Length];
            Array.Copy(nonce, 0, payload, 0, 12);
            Array.Copy(tag, 0, payload, 12, 16);
            Array.Copy(ciphertext, 0, payload, 28, ciphertext.Length);

            return payload;
        }

        public static byte[] DecryptBytes(byte[] payload, byte[] key)
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
