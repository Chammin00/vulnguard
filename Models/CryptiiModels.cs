namespace vulnerability_management.Models;

public class CryptiiTransformRequest
{
    public string InputText { get; set; } = string.Empty;
    public string Method { get; set; } = "Base64_Encode";
    public string KeyOrSecret { get; set; } = string.Empty;
    public string ExtraParam { get; set; } = string.Empty;
}

public class CryptiiTransformResult
{
    public string OutputText { get; set; } = string.Empty;
    public bool IsSuccess { get; set; } = true;
    public string ErrorMessage { get; set; } = string.Empty;
    public string MethodUsed { get; set; } = string.Empty;
    public int InputLength { get; set; }
    public int OutputLength { get; set; }
    public Dictionary<string, string> Metadata { get; set; } = new();
}

public class RsaKeyPairResult
{
    public string PublicKeyPem { get; set; } = string.Empty;
    public string PrivateKeyPem { get; set; } = string.Empty;
    public int KeySizeBits { get; set; } = 2048;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
