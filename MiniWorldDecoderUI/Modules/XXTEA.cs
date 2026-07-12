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

        var padLen = result[^1];
        if (padLen < 4)
            Array.Resize(ref result, result.Length - padLen);

        return result;
    }

    private static void Decrypt(uint[] v, uint[] key)
    {
        int n = v.Length;
        if (n < 2) return;

        uint y = v[0];
        uint sum;
        uint e;
        int p;

        sum = (uint)(Delta * (6 + 52.0 / n));
        uint q = (uint)(6 + 52 / n);

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
