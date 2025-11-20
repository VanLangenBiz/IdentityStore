using PwrCsr2;
using System.Security.Cryptography;

internal static class PrivateKeyHelper
{
    const string PrivateKeyBegin = "-----BEGIN PWR AES256 TPM ENCRYPTED PRIVATE KEY-----";
    const string PrivateKeyEnd = "-----END PWR AES256 TPM ENCRYPTED PRIVATE KEY-----";

    public static RSA GetOrCreatePrivateKey(string privKeyEncPath, byte[] encryptionKey)
    {
        if (File.Exists(privKeyEncPath))
            return ReadEncryptedPrivate(privKeyEncPath, encryptionKey);

        return WriteEncryptedPrivateKey(privKeyEncPath, encryptionKey);
    }

    public static RSA ReadEncryptedPrivate(string privKeyEncPath, byte[] encryptionKey)
    {
        var pem = File.ReadAllText(privKeyEncPath);

        // Strip PEM headers
        var base64 = pem
            .Replace(PrivateKeyBegin, "")
            .Replace(PrivateKeyEnd, "")
            .Replace("\n", "")
            .Replace("\r", "")
            .Trim();

        // Base64 decode
        var encryptedPkcs8 = Convert.FromBase64String(base64);

        // AES decrypt
        var pkcs8Bytes = CertHelpers.AesDecrypt(encryptedPkcs8, encryptionKey);

        // Import PKCS#8
        var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(pkcs8Bytes, out _);

        return rsa;
    }

    public static RSA WriteEncryptedPrivateKey(string filename, byte[] encryptionKey)
    {
        // Nieuwe key pair genereren
        var rsa = RSA.Create(2048);

        // PKCS#8 private key (DER)
        var pkcs8Bytes = rsa.ExportPkcs8PrivateKey();

        // Encrypt PKCS#8
        var encrypted = CertHelpers.AesEncrypt(pkcs8Bytes, encryptionKey);

        // Base64 encode
        var base64 = Convert.ToBase64String(encrypted, Base64FormattingOptions.InsertLineBreaks);

        // PEM structure
        var pem =
            PrivateKeyBegin + "\n" +
            base64 + "\n" +
            PrivateKeyEnd + "\n";

        File.WriteAllText(filename, pem);

        return rsa;
    }
}
