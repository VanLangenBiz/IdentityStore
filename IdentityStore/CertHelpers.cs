using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PwrCsr2
{
    internal class CertHelpers
    {
        private const string PWRCertKey = "PWRCertKey";

        public static void EnsureTpmKeyExists()
        {
            try
            {
                using (var _ = CngKey.Open(PWRCertKey, new CngProvider("Microsoft Platform Crypto Provider"))) ;
                    //_.Delete();
            }
            catch (CryptographicException)
            {
                var parms = new CngKeyCreationParameters
                {
                    Provider = new CngProvider("Microsoft Platform Crypto Provider"),
                    ExportPolicy = CngExportPolicies.None,
                    KeyUsage = CngKeyUsages.AllUsages
                };

                parms.Parameters.Add(new CngProperty(
                    "Key Usage",
                    BitConverter.GetBytes(
                        (int)(
                            0x00000002 | // NCRYPT_ALLOW_DECRYPT_FLAG
                            0x00000001   // NCRYPT_ALLOW_ENCRYPT_FLAG
                        )
                    ),
                    CngPropertyOptions.None
                ));
                CngKey.Create(CngAlgorithm.Rsa, PWRCertKey, parms);
            }
        }

        public static byte[] GenerateRandomChars(int length = 32)
        {
            var pwdBytes = new byte[length];

            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(pwdBytes);

            return pwdBytes;
        }

        public static byte[] TpmEncrypt(byte[] plaintext)
        {
            using (var tpmKey = CngKey.Open(PWRCertKey, new CngProvider("Microsoft Platform Crypto Provider")))
            using (var rsa = new RSACng(tpmKey))
                return rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
        }

        public static byte[] TpmDecrypt(byte[] ciphertext)
        {
            using (var tpmKey = CngKey.Open(PWRCertKey, new CngProvider("Microsoft Platform Crypto Provider")))
            using (var rsa = new RSACng(tpmKey))
                return rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
        }

        public static byte[] AesEncrypt(byte[] plaintext, byte[] key)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.GenerateIV();

                using (var ms = new MemoryStream())
                {
                    ms.Write(aes.IV, 0, aes.IV.Length);

                    using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(plaintext, 0, plaintext.Length);
                    }

                    return ms.ToArray(); // [IV][CIPHERTEXT]
                }
            }
        }

        public static byte[] AesDecrypt(byte[] ciphertextWithIv, byte[] key)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var ms = new MemoryStream(ciphertextWithIv))
                {

                    var iv = new byte[aes.BlockSize / 8];
                    ms.Read(iv, 0, iv.Length);
                    aes.IV = iv;

                    using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    using (var plainMs = new MemoryStream())
                    {
                        cs.CopyTo(plainMs);
                        return plainMs.ToArray();
                    }
                }
            }
        }
    }
}
