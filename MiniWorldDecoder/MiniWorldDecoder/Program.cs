using MiniWorldDecoder.Modules;

// Usage: MiniWorldDecoder [path] [-o output_dir]
var inputPath = args.Length > 0 && !args[0].StartsWith("-") ? args[0] : Directory.GetCurrentDirectory();
var outputDir = "decrypted";

for (int i = 0; i < args.Length; i++)
{
    if (args[i] == "-o" && i + 1 < args.Length)
        outputDir = args[i + 1];
}

// Obfuscated XXTEA key: hex -> ASCII -> XOR mask
byte[] masked = [0xb7,0x31,0xa0,0xd9,0x55,0xef,0xb9,0x66,0x8b,0x5a,0xb9,0xb4,0x6a,0x3a,0xd0,0x4b,0xe5,0x65,0x7d,0x58,0x13,0x50,0x99,0x91,0x3c,0x8f,0x9a,0x3f,0xed,0x62,0x65,0x67];
byte[] mask   = [0xd5,0x05,0x98,0xbc,0x63,0x8a,0xdf,0x52,0xbf,0x3f,0xdd,0x85,0x59,0x5f,0xb5,0x2e,0xd3,0x55,0x4b,0x69,0x27,0x61,0xae,0xa4,0x0c,0xea,0xad,0x0d,0xd4,0x01,0x03,0x53];
var hexChars = new char[32];
for (int i = 0; i < 32; i++)
    hexChars[i] = (char)(masked[i] ^ mask[i]);
var hexStr = new string(hexChars);
var keyBytes = Convert.FromHexString(hexStr);

Console.WriteLine("Key: [protected]");
Console.WriteLine();

// Find all Lua files
var files = new List<string>();
if (Directory.Exists(inputPath))
{
    files.AddRange(Directory.GetFiles(inputPath, "*.lua", SearchOption.AllDirectories));
    files.AddRange(Directory.GetFiles(inputPath, "*.wsc", SearchOption.AllDirectories));
}
else if (File.Exists(inputPath))
{
    files.Add(inputPath);
}
else
{
    Console.Error.WriteLine($"Error: {inputPath} not found");
    return 1;
}

Console.WriteLine($"Found {files.Count} files");
Console.WriteLine($"Output: {outputDir}");
Console.WriteLine();

var success = 0;
var fail = 0;
var skip = 0;

foreach (var file in files)
{
    var raw = File.ReadAllBytes(file);
    var text = System.Text.Encoding.UTF8.GetString(raw);
    var header = BitConverter.ToString(raw.Take(24).ToArray()).Replace("-", " ");

    // Check for BOM
    if (text.StartsWith('\uFEFF'))
        text = text[1..];

    string b64;
    if (text.StartsWith("a0817i") && text.Length > 6)
        b64 = text[6..].Trim();
    else
    {
        var trimmed = text.Trim();
        if (trimmed.Length >= 30 && trimmed.All(c => char.IsAsciiLetterOrDigit(c) || c == '+' || c == '/' || c == '='))
            b64 = trimmed;
        else
        {
            skip++;
            continue;
        }
    }

    var cipherBytes = Convert.FromBase64String(b64);
    var decrypted = XXTEA.Decrypt(cipherBytes, keyBytes);

    if (decrypted.Length == cipherBytes.Length && decrypted.SequenceEqual(cipherBytes))
    {
        Console.WriteLine($"  FAIL: {file}");
        Console.WriteLine($"    Raw header: {header}");
        fail++;
        continue;
    }

    var content = System.Text.Encoding.UTF8.GetString(decrypted);
    var relPath = Path.GetRelativePath(
        Directory.Exists(inputPath) ? inputPath : Path.GetDirectoryName(inputPath)!,
        file
    );
    var outFile = Path.Combine(outputDir, relPath);
    Directory.CreateDirectory(Path.GetDirectoryName(outFile)!);
    File.WriteAllText(outFile, content);

    var lines = content.Split('\n');
    var previewLines = lines.Take(6).Select(l => l.TrimEnd('\r'));
    var preview = string.Join("\n    ", previewLines);
    var more = lines.Length > 6 ? $"  \u2502 ... ({lines.Length - 6} d\u00f2ng n\u1eefa)" : "";
    Console.WriteLine($"  OK ({content.Length,6}B) {relPath}");
    Console.WriteLine($"    {preview}");
    if (more.Length > 0) Console.WriteLine(more);
    Console.WriteLine();
    success++;
}

Console.WriteLine($"\nDone: {success} decoded, {fail} failed, {skip} skipped");
return 0;
