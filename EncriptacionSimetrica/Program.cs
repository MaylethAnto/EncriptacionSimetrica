using System;
using System.Text;
using System.Security.Cryptography;

namespace EncriptacionSimetrica
{
    public class Program
    {
        private static byte[] clave;
        private static byte[] iv;

        public static void Main(string[] args)
        {
            Console.WriteLine("Ingresa tu usuario:");
            string usuario = Console.ReadLine();

            Console.WriteLine("Ingresa tu clave:");
            string contrasena = Console.ReadLine();

            Console.WriteLine("Ingresa tu mensaje:");
            string mensaje = Console.ReadLine();

            // Generar clave y IV
            clave = CryptoUtils.GenerateClave();
            iv = CryptoUtils.GenerateIV();

            // Encriptar la clave y el mensaje
            byte[] contrasenaEncriptada = CryptoUtils.EncriptarDatos(Encoding.UTF8.GetBytes(contrasena), clave, iv);
            byte[] mensajeEncriptado = CryptoUtils.EncriptarDatos(Encoding.UTF8.GetBytes(mensaje), clave, iv);

            // Convertir la clave encriptada a Base64 para comparación
            string contrasenaEncriptadaBase64 = Convert.ToBase64String(contrasenaEncriptada);

            // Imprimir la clave y el mensaje encriptados
            Console.WriteLine("La clave encriptada es: " + contrasenaEncriptadaBase64);
            Console.WriteLine("El mensaje encriptado es: " + Convert.ToBase64String(mensajeEncriptado));

            // Proceso de desencriptación
            const int maxIntentos = 3;
            bool desencriptadoExitoso = false;

            for (int intentos = 0; intentos < maxIntentos && !desencriptadoExitoso; intentos++)
            {
                Console.WriteLine("Ingresa la clave para desencriptar:");
                string claveParaDesencriptar = Console.ReadLine();
                byte[] claveParaDesencriptarEncriptada = CryptoUtils.EncriptarDatos(Encoding.UTF8.GetBytes(claveParaDesencriptar), clave, iv);

                if (CompararBytes(contrasenaEncriptada, claveParaDesencriptarEncriptada))
                {
                    byte[] mensajeDesencriptado = CryptoUtils.DesencriptarDatos(mensajeEncriptado, clave, iv);
                    Console.WriteLine("El mensaje desencriptado es: " + Encoding.UTF8.GetString(mensajeDesencriptado));
                    desencriptadoExitoso = true;
                }
                else
                {
                    Console.WriteLine("Clave incorrecta. Vuelve a ingresar la clave.");
                }
            }

            if (!desencriptadoExitoso)
            {
                Console.WriteLine("Demasiados intentos fallidos. No se puede desencriptar el mensaje.");
            }

            Console.ReadLine();
        }

        private static bool CompararBytes(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;

            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }
    }

    public static class CryptoUtils
    {
        public static byte[] GenerateClave()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] key = new byte[32]; // 256 bits
                rng.GetBytes(key);
                return key;
            }
        }

        public static byte[] GenerateIV()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] iv = new byte[16]; // 128 bits
                rng.GetBytes(iv);
                return iv;
            }
        }

        public static byte[] EncriptarDatos(byte[] datos, byte[] clave, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = clave;
                aes.IV = iv;
                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    return PerformCryptography(datos, encryptor);
                }
            }
        }

        public static byte[] DesencriptarDatos(byte[] datos, byte[] clave, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = clave;
                aes.IV = iv;
                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    return PerformCryptography(datos, decryptor);
                }
            }
        }

        private static byte[] PerformCryptography(byte[] datos, ICryptoTransform cryptoTransform)
        {
            using (var ms = new System.IO.MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(datos, 0, datos.Length);
                    cryptoStream.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }
    }
}
