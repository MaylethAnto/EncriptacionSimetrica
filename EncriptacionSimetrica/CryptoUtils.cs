using System;
using System.IO;
using System.Security.Cryptography;

public class CryptoUtils
{
    public static byte[] GenerateClave()
    {
        using (Aes miAes = Aes.Create())
        {
            miAes.KeySize = 256;
            miAes.GenerateKey();
            return miAes.Key;
        }
    }

    public static byte[] GenerateIV()
    {
        using (Aes miAes = Aes.Create())
        {
            miAes.GenerateIV();
            return miAes.IV;
        }
    }

    public static byte[] EncriptarDatos(byte[] datos, byte[] clave, byte[] iv)
    {
        using (Aes miAes = Aes.Create())
        {
            miAes.Key = clave;
            miAes.IV = iv;
            miAes.Padding = PaddingMode.PKCS7;

            ICryptoTransform encriptador = miAes.CreateEncryptor(miAes.Key, miAes.IV);

            using (MemoryStream msEncriptar = new MemoryStream())
            {
                using (CryptoStream csEncriptar = new CryptoStream(msEncriptar, encriptador, CryptoStreamMode.Write))
                {
                    csEncriptar.Write(datos, 0, datos.Length);
                    csEncriptar.FlushFinalBlock();

                    return msEncriptar.ToArray();
                }
            }
        }
    }

    public static byte[] DesencriptarDatos(byte[] datos, byte[] clave, byte[] iv)
    {
        using (Aes miAes = Aes.Create())
        {
            miAes.Key = clave;
            miAes.IV = iv;
            miAes.Padding = PaddingMode.PKCS7;

            ICryptoTransform desencriptador = miAes.CreateDecryptor(miAes.Key, miAes.IV);

            using (MemoryStream msDesencriptar = new MemoryStream(datos))
            {
                using (CryptoStream csDesencriptar = new CryptoStream(msDesencriptar, desencriptador, CryptoStreamMode.Read))
                {
                    using (MemoryStream msDesencriptado = new MemoryStream())
                    {
                        byte[] bufferDataDescifrada = new byte[datos.Length];
                        int leido = csDesencriptar.Read(bufferDataDescifrada, 0, datos.Length);
                        msDesencriptado.Write(bufferDataDescifrada, 0, leido);

                        return msDesencriptado.ToArray();
                    }
                }
            }
        }
    }
}
