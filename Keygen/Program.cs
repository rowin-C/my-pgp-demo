// using System;
// using System.IO;
// using System.Text;
// using Org.BouncyCastle.Bcpg;
// using Org.BouncyCastle.Bcpg.OpenPgp;
// using Org.BouncyCastle.Crypto;
// using Org.BouncyCastle.Crypto.Generators;
// using Org.BouncyCastle.Crypto.Parameters;
// using Org.BouncyCastle.Security;
//
// namespace Keygen
// {
//     class Program
//     {
//         static void Main(string[] args)
//         {
//             var keys = GeneratePgpKeys("test@example.com");
//
//             Console.WriteLine("----- PUBLIC KEY -----");
//             Console.WriteLine(keys.publicKey);
//             Console.WriteLine("----- PRIVATE KEY -----");
//             Console.WriteLine(keys.privateKey);
//         }
//
//         public static (string publicKey, string privateKey) GeneratePgpKeys(string identity)
//         {
//             var rsa = new RsaKeyPairGenerator();
//             rsa.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
//             AsymmetricCipherKeyPair keyPair = rsa.GenerateKeyPair();
//
//             // Build PGP key pair
//             var pgpKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, keyPair, DateTime.UtcNow);
//
//             // Add key flags
// var hashedSubPackets = new PgpSignatureSubpacketGenerator();
// hashedSubPackets.SetKeyFlags(false, PgpKeyFlags.CanSign | PgpKeyFlags.CanCertify);
//
// var keyRingGen = new PgpKeyRingGenerator(
//     PgpSignature.DefaultCertification,
//     pgpKeyPair,
//     identity,
//     SymmetricKeyAlgorithmTag.Aes256,
//     new char[0], // no password
//     true,
//     hashedSubPackets.Generate(),
//     null,
//     new SecureRandom()
// );            var publicRing = keyRingGen.GeneratePublicKeyRing();
//             var secretRing = keyRingGen.GenerateSecretKeyRing();
//
//             string pubKey = EncodeKeyRing(publicRing);
//             string privKey = EncodeKeyRing(secretRing);
//
//             return (pubKey, privKey);
//         }
//
//         private static string EncodeKeyRing(object keyRing)
// {
//     using (var mem = new MemoryStream())
//     {
//         using (var armor = new ArmoredOutputStream(mem))
//         {
//             armor.SetHeader("Version", null); // remove Version header
//
//             if (keyRing is PgpPublicKeyRing pub)
//             {
//                 pub.Encode(armor);
//             }
//             else if (keyRing is PgpSecretKeyRing sec)
//             {
//                 sec.Encode(armor);
//             }
//             else
//             {
//                 throw new ArgumentException("Unsupported key ring type");
//             }
//
//             armor.Close(); // ✅ ensure END block is written
//         }
//
//         return Encoding.UTF8.GetString(mem.ToArray())
//                             .Replace("\r\n", "\n"); // LF only
//     }
// }
//     }
// }

using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;

namespace Keygen
{
    class Program
    {
        static void Main(string[] args)
        {
            var keys = GeneratePgpKeys("test@example.com");

            Console.WriteLine("----- PUBLIC KEY -----");
            Console.WriteLine(keys.publicKey);
            Console.WriteLine("----- PRIVATE KEY -----");
            Console.WriteLine(keys.privateKey);
        }

        public static (string publicKey, string privateKey) GeneratePgpKeys(string identity)
        {
            // Generate master (signing) key
            var rsaSign = new RsaKeyPairGenerator();
            rsaSign.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair signPair = rsaSign.GenerateKeyPair();

            var masterKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, signPair, DateTime.UtcNow);

            // Flags for signing master key
            var masterPackets = new PgpSignatureSubpacketGenerator();
            masterPackets.SetKeyFlags(false, PgpKeyFlags.CanSign | PgpKeyFlags.CanCertify);
            char[] passphrase = "myStrongPassphrase".ToCharArray();

            var keyRingGen = new PgpKeyRingGenerator(
                PgpSignature.DefaultCertification,
                masterKeyPair,
                identity,
                SymmetricKeyAlgorithmTag.Aes256,
                passphrase,
                true,   // unprotected
                masterPackets.Generate(),
                null,
                new SecureRandom()
            );

            // Generate encryption subkey
            var rsaEnc = new RsaKeyPairGenerator();
            rsaEnc.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair encPair = rsaEnc.GenerateKeyPair();
            var encPgpKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, encPair, DateTime.UtcNow);

            var encPackets = new PgpSignatureSubpacketGenerator();
            encPackets.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);

            keyRingGen.AddSubKey(encPgpKeyPair, encPackets.Generate(), null);

            // Export keys
            var publicRing = keyRingGen.GeneratePublicKeyRing();
            var secretRing = keyRingGen.GenerateSecretKeyRing();

            string pubKey = EncodeKeyRing(publicRing);
            string privKey = EncodeKeyRing(secretRing);

            return (pubKey, privKey);
        }

        private static string EncodeKeyRing(object keyRing)
        {
            using (var mem = new MemoryStream())
            {
                using (var armor = new ArmoredOutputStream(mem))
                {
                    armor.SetHeader("Version", null); // remove Version header

                    if (keyRing is PgpPublicKeyRing pub)
                    {
                        pub.Encode(armor);
                    }
                    else if (keyRing is PgpSecretKeyRing sec)
                    {
                        sec.Encode(armor);
                    }
                    else
                    {
                        throw new ArgumentException("Unsupported key ring type");
                    }

                    armor.Close(); // ensure END block is written
                }

                return Encoding.UTF8.GetString(mem.ToArray())
                                    .Replace("\r\n", "\n"); // LF only
            }
        }
    }
}

