
using PwrCsr2;

public static class PasswordEncryptionLoader
{
    const string encPwdEnvName = "PWR_TLS_PFX_PWD_ENC";

    public static byte[] GetOrCreateDecryptionKey()
    {
        byte[] pwdBytes;
        //string pfxPassword;

        var encPwdBase64 = Environment.GetEnvironmentVariable(encPwdEnvName, EnvironmentVariableTarget.User);
        if (string.IsNullOrEmpty(encPwdBase64))
        {
            // nieuw random password
            pwdBytes = TpmUtils.GenerateRandomChars();
            //pfxPassword = Convert.ToBase64String(pwdBytes); // string voor PFX

            var encPwdBytes = TpmUtils.TpmEncrypt(pwdBytes);
            encPwdBase64 = Convert.ToBase64String(encPwdBytes);

            Environment.SetEnvironmentVariable(encPwdEnvName, encPwdBase64, EnvironmentVariableTarget.User);
        }
        else
        {
            var encPwdBytes = Convert.FromBase64String(encPwdBase64);
            pwdBytes = TpmUtils.TpmDecrypt(encPwdBytes);
            //pfxPassword = Convert.ToBase64String(pwdBytes);
        }

        return pwdBytes;
    }

}

