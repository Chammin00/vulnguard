using System.Security.Cryptography;
using System.Text;
using System.Web;
using vulnerability_management.Models;

namespace vulnerability_management.Services;

public interface ICryptiiService
{
    CryptiiTransformResult Transform(CryptiiTransformRequest request);
    RsaKeyPairResult GenerateRsaKeyPair(int keySize = 2048);
}

public class CryptiiService : ICryptiiService
{
    private static readonly Dictionary<char, string> MorseCodeMap = new()
    {
        {'A', ".-"}, {'B', "-..."}, {'C', "-.-."}, {'D', "-.."}, {'E', "."},
        {'F', "..-."}, {'G', "--."}, {'H', "...."}, {'I', ".."}, {'J', ".---"},
        {'K', "-.-"}, {'L', ".-.."}, {'M', "--"}, {'N', "-."}, {'O', "---"},
        {'P', ".--."}, {'Q', "--.-"}, {'R', ".-."}, {'S', "..."}, {'T', "-"},
        {'U', "..-"}, {'V', "...-"}, {'W', ".--"}, {'X', "-..-"}, {'Y', "-.--"},
        {'Z', "--.."}, {'1', ".----"}, {'2', "..---"}, {'3', "...--"}, {'4', "....-"},
        {'5', "....."}, {'6', "-...."}, {'7', "--..."}, {'8', "---.."}, {'9', "----."},
        {'0', "-----"}, {' ', "/"}
    };

    private static readonly Dictionary<string, char> ReverseMorseMap =
        MorseCodeMap.ToDictionary(kvp => kvp.Value, kvp => kvp.Key);

    public CryptiiTransformResult Transform(CryptiiTransformRequest request)
    {
        var result = new CryptiiTransformResult
        {
            MethodUsed = request.Method,
            InputLength = request.InputText?.Length ?? 0
        };

        var text = request.InputText ?? "";

        try
        {
            switch (request.Method?.ToLowerInvariant())
            {
                // 1. BASE64
                case "base64_encode":
                    result.OutputText = Convert.ToBase64String(Encoding.UTF8.GetBytes(text));
                    break;
                case "base64_decode":
                    result.OutputText = Encoding.UTF8.GetString(Convert.FromBase64String(text.Trim()));
                    break;

                // 2. HEXADECIMAL
                case "hex_encode":
                    result.OutputText = string.Join(" ", Encoding.UTF8.GetBytes(text).Select(b => b.ToString("x2")));
                    break;
                case "hex_decode":
                    var cleanHex = text.Replace(" ", "").Replace("0x", "").Replace(":", "").Replace("-", "").Trim();
                    byte[] rawBytes = Convert.FromHexString(cleanHex);
                    result.OutputText = Encoding.UTF8.GetString(rawBytes);
                    break;

                // 3. BINARY
                case "binary_encode":
                    result.OutputText = string.Join(" ", Encoding.UTF8.GetBytes(text).Select(b => Convert.ToString(b, 2).PadLeft(8, '0')));
                    break;
                case "binary_decode":
                    var binTokens = text.Split(new[] { ' ', '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    var binBytes = binTokens.Select(b => Convert.ToByte(b, 2)).ToArray();
                    result.OutputText = Encoding.UTF8.GetString(binBytes);
                    break;

                // 4. URL ENCODING
                case "url_encode":
                    result.OutputText = Uri.EscapeDataString(text);
                    break;
                case "url_decode":
                    result.OutputText = Uri.UnescapeDataString(text);
                    break;

                // 5. HTML ENTITIES
                case "html_encode":
                    result.OutputText = HttpUtility.HtmlEncode(text);
                    break;
                case "html_decode":
                    result.OutputText = HttpUtility.HtmlDecode(text);
                    break;

                // 6. MORSE CODE
                case "morse_encode":
                    var upper = text.ToUpperInvariant();
                    var morseTokens = new List<string>();
                    foreach (var c in upper)
                    {
                        if (MorseCodeMap.TryGetValue(c, out var m))
                            morseTokens.Add(m);
                    }
                    result.OutputText = string.Join(" ", morseTokens);
                    break;
                case "morse_decode":
                    var morseWords = text.Split(" / ");
                    var decodedWords = new List<string>();
                    foreach (var w in morseWords)
                    {
                        var chars = w.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                        var wordBuilder = new StringBuilder();
                        foreach (var token in chars)
                        {
                            if (ReverseMorseMap.TryGetValue(token, out var ch))
                                wordBuilder.Append(ch);
                        }
                        decodedWords.Add(wordBuilder.ToString());
                    }
                    result.OutputText = string.Join(" ", decodedWords);
                    break;

                // 7. ROT13 & ROT47
                case "rot13":
                    result.OutputText = ApplyRot13(text);
                    break;
                case "rot47":
                    result.OutputText = ApplyRot47(text);
                    break;

                // 8. CAESAR CIPHER
                case "caesar_encode":
                    int shift = int.TryParse(request.KeyOrSecret, out var s) ? s : 3;
                    result.OutputText = ApplyCaesar(text, shift);
                    break;
                case "caesar_decode":
                    int unshift = int.TryParse(request.KeyOrSecret, out var us) ? us : 3;
                    result.OutputText = ApplyCaesar(text, -unshift);
                    break;

                // 9. VIGENERE CIPHER
                case "vigenere_encode":
                    result.OutputText = ApplyVigenere(text, request.KeyOrSecret, false);
                    break;
                case "vigenere_decode":
                    result.OutputText = ApplyVigenere(text, request.KeyOrSecret, true);
                    break;

                // 10. ATBASH CIPHER
                case "atbash":
                    result.OutputText = ApplyAtbash(text);
                    break;

                // 11. XOR CIPHER
                case "xor":
                    result.OutputText = ApplyXor(text, string.IsNullOrWhiteSpace(request.KeyOrSecret) ? "SECRET" : request.KeyOrSecret);
                    break;

                // 12. AES-256-CBC ENCRYPTION
                case "aes_encrypt":
                    result.OutputText = AesEncrypt(text, string.IsNullOrWhiteSpace(request.KeyOrSecret) ? "VulnGuardSecureKey" : request.KeyOrSecret, result.Metadata);
                    break;
                case "aes_decrypt":
                    result.OutputText = AesDecrypt(text, string.IsNullOrWhiteSpace(request.KeyOrSecret) ? "VulnGuardSecureKey" : request.KeyOrSecret);
                    break;

                // 13. HMAC-SHA256
                case "hmac_sha256":
                    var keyBytes = Encoding.UTF8.GetBytes(string.IsNullOrWhiteSpace(request.KeyOrSecret) ? "SecretKey" : request.KeyOrSecret);
                    using (var hmac = new HMACSHA256(keyBytes))
                    {
                        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(text));
                        result.OutputText = Convert.ToHexStringLower(hash);
                    }
                    break;

                default:
                    result.OutputText = Convert.ToBase64String(Encoding.UTF8.GetBytes(text));
                    break;
            }

            result.OutputLength = result.OutputText.Length;
        }
        catch (Exception ex)
        {
            result.IsSuccess = false;
            result.ErrorMessage = $"Transformation failed: {ex.Message}";
        }

        return result;
    }

    public RsaKeyPairResult GenerateRsaKeyPair(int keySize = 2048)
    {
        using var rsa = RSA.Create(keySize);
        return new RsaKeyPairResult
        {
            KeySizeBits = keySize,
            PublicKeyPem = rsa.ExportRSAPublicKeyPem(),
            PrivateKeyPem = rsa.ExportRSAPrivateKeyPem(),
            CreatedAt = DateTime.UtcNow
        };
    }

    private static string ApplyRot13(string input)
    {
        char[] array = input.ToCharArray();
        for (int i = 0; i < array.Length; i++)
        {
            int number = array[i];
            if (number >= 'a' && number <= 'z')
            {
                if (number > 'm') number -= 13;
                else number += 13;
            }
            else if (number >= 'A' && number <= 'Z')
            {
                if (number > 'M') number -= 13;
                else number += 13;
            }
            array[i] = (char)number;
        }
        return new string(array);
    }

    private static string ApplyRot47(string input)
    {
        char[] array = input.ToCharArray();
        for (int i = 0; i < array.Length; i++)
        {
            int ch = array[i];
            if (ch >= 33 && ch <= 126)
            {
                array[i] = (char)(33 + ((ch + 14) % 94));
            }
        }
        return new string(array);
    }

    private static string ApplyCaesar(string text, int shift)
    {
        shift %= 26;
        if (shift < 0) shift += 26;

        char[] buffer = text.ToCharArray();
        for (int i = 0; i < buffer.Length; i++)
        {
            char c = buffer[i];
            if (char.IsUpper(c))
            {
                buffer[i] = (char)('A' + ((c - 'A' + shift) % 26));
            }
            else if (char.IsLower(c))
            {
                buffer[i] = (char)('a' + ((c - 'a' + shift) % 26));
            }
        }
        return new string(buffer);
    }

    private static string ApplyVigenere(string text, string key, bool decrypt)
    {
        if (string.IsNullOrWhiteSpace(key)) return text;
        key = key.ToUpperInvariant();

        var sb = new StringBuilder();
        int keyIndex = 0;

        foreach (char c in text)
        {
            if (char.IsLetter(c))
            {
                bool isUpper = char.IsUpper(c);
                int offset = isUpper ? 'A' : 'a';
                int shift = key[keyIndex % key.Length] - 'A';
                if (decrypt) shift = 26 - shift;

                int code = (c - offset + shift) % 26;
                sb.Append((char)(offset + code));
                keyIndex++;
            }
            else
            {
                sb.Append(c);
            }
        }
        return sb.ToString();
    }

    private static string ApplyAtbash(string text)
    {
        char[] buffer = text.ToCharArray();
        for (int i = 0; i < buffer.Length; i++)
        {
            char c = buffer[i];
            if (c >= 'A' && c <= 'Z')
            {
                buffer[i] = (char)('Z' - (c - 'A'));
            }
            else if (c >= 'a' && c <= 'z')
            {
                buffer[i] = (char)('z' - (c - 'a'));
            }
        }
        return new string(buffer);
    }

    private static string ApplyXor(string text, string key)
    {
        byte[] textBytes = Encoding.UTF8.GetBytes(text);
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] result = new byte[textBytes.Length];

        for (int i = 0; i < textBytes.Length; i++)
        {
            result[i] = (byte)(textBytes[i] ^ keyBytes[i % keyBytes.Length]);
        }

        return Convert.ToHexStringLower(result);
    }

    private static string AesEncrypt(string plainText, string password, Dictionary<string, string> metadata)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] iv = RandomNumberGenerator.GetBytes(16);

        metadata["SaltHex"] = Convert.ToHexStringLower(salt);
        metadata["IvHex"] = Convert.ToHexStringLower(iv);

        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);
        byte[] key = pbkdf2.GetBytes(32); // AES-256

        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using var ms = new MemoryStream();
        // Write salt + IV prefix into payload
        ms.Write(salt, 0, salt.Length);
        ms.Write(iv, 0, iv.Length);

        using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
        using (var sw = new StreamWriter(cs, Encoding.UTF8))
        {
            sw.Write(plainText);
        }

        return Convert.ToBase64String(ms.ToArray());
    }

    private static string AesDecrypt(string cipherBase64, string password)
    {
        byte[] allBytes = Convert.FromBase64String(cipherBase64.Trim());
        if (allBytes.Length < 32) throw new ArgumentException("Invalid AES ciphertext payload format.");

        byte[] salt = new byte[16];
        byte[] iv = new byte[16];
        Array.Copy(allBytes, 0, salt, 0, 16);
        Array.Copy(allBytes, 16, iv, 0, 16);

        byte[] cipherBytes = new byte[allBytes.Length - 32];
        Array.Copy(allBytes, 32, cipherBytes, 0, cipherBytes.Length);

        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);
        byte[] key = pbkdf2.GetBytes(32);

        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using var ms = new MemoryStream(cipherBytes);
        using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
        using var sr = new StreamReader(cs, Encoding.UTF8);

        return sr.ReadToEnd();
    }
}
