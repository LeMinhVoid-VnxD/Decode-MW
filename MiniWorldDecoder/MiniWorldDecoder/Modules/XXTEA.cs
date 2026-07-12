namespace MiniWorldDecoder.Modules;

public static class XXTEA
{
    private const uint Delta = 0x9E3779B9;

    public static byte[] Decrypt(byte[] data, byte[] key)
    {
        if (data.Length < 8 || key.Length < 4)
            return data;

        var k = new uint[4];
        for (int i = 0; i < 4; i++)
            k[i] = key.Length > i * 4 ? BitConverter.ToUInt32(GetPaddedKey(key, i * 4)) : 0;

        var n = data.Length / 4;
        if (n < 2) return data;

        var v = new uint[n];
        Buffer.BlockCopy(data, 0, v, 0, data.Length - (data.Length % 4));

        try
        {
            Decrypt(v, k);
        }
        catch
        {
            return data;
        }

        var result = new byte[v.Length * 4];
        Buffer.BlockCopy(v, 0, result, 0, result.Length);

        // MiniWorld custom format: first 4 bytes = big-endian plaintext length
        if (result.Length >= 4)
        {
            var plainLen = (uint)(result[0] << 24) | (uint)(result[1] << 16) | (uint)(result[2] << 8) | result[3];
            if (plainLen > 0 && plainLen + 4 <= result.Length)
                return result[4..(int)(4 + plainLen)];
        }

        return result;
    }

    private static void Decrypt(uint[] v, uint[] key)
    {
        int n = v.Length;
        if (n < 2) return;

        uint y = v[0];
        uint e;
        int p;

        uint q = (uint)(6 + 52 / n);
        uint sum = q * Delta;

        while (q-- > 0)
        {
            e = (sum >> 2) & 3;
            for (p = n - 1; p > 0; p--)
            {
                uint z = v[p - 1];
                v[p] -= (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z));
                y = v[p];
            }
            uint z0 = v[n - 1];
            v[0] -= (((z0 >> 5) ^ (y << 2)) + ((y >> 3) ^ (z0 << 4))) ^ ((sum ^ y) + (key[(0 & 3) ^ e] ^ z0));
            y = v[0];
            sum -= Delta;
        }
    }

    private static byte[] GetPaddedKey(byte[] key, int offset)
    {
        var buf = new byte[4];
        for (int i = 0; i < 4; i++)
            buf[i] = offset + i < key.Length ? key[offset + i] : (byte)0;
        return buf;
    }

    public static byte[] DeriveKeyFromString(string password)
    {
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        return sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
    }

    public static byte[]? TryParseKey(string input)
    {
        if (string.IsNullOrEmpty(input)) return null;

        // Try Hex string (32 hex chars = 16 bytes)
        if (input.Length == 32 && System.Text.RegularExpressions.Regex.IsMatch(input, @"\A[0-9a-fA-F]{32}\z"))
        {
            var result = new byte[16];
            for (int i = 0; i < 16; i++)
                result[i] = Convert.ToByte(input.Substring(i * 2, 2), 16);
            return result;
        }

        // Try Base64 decode first
        try
        {
            var decoded = Convert.FromBase64String(input);
            if (decoded.Length >= 4)
                return decoded;
        }
        catch { }

        // Try UTF8 bytes
        var utf8 = System.Text.Encoding.UTF8.GetBytes(input);
        if (utf8.Length >= 4)
            return utf8;

        return DeriveKeyFromString(input);
    }
}
