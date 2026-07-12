using MiniWorldDecoder.Models;

namespace MiniWorldDecoder.Modules;

public class LuaProcessor
{
    private static readonly byte[] LuaSig = { 0x1B, 0x4C, 0x75, 0x61 };

    public DecodeResult Decode(string filePath, string outputDir)
    {
        return Decode(filePath, outputDir, null);
    }

    public DecodeResult Decode(string filePath, string outputDir, string? xxteaKey)
    {
        var result = new DecodeResult
        {
            FilePath = filePath,
            FileType = "Lua Script",
            FileSize = new FileInfo(filePath).Length
        };

        try
        {
            var raw = File.ReadAllBytes(filePath);
            Directory.CreateDirectory(outputDir);

            var data = raw;
            if (!string.IsNullOrEmpty(xxteaKey))
            {
                var keyBytes = XXTEA.TryParseKey(xxteaKey);
                if (keyBytes == null)
                {
                    result.Errors.Add("Key XXTEA không hợp lệ");
                    result.Success = false;
                    return result;
                }

                var decrypted = XXTEA.Decrypt(data, keyBytes);
                if (decrypted != data && IsValidLuaData(decrypted))
                {
                    result.Metadata["XXTEA"] = "Decrypted successfully";
                    result.Metadata["XXTEAKey"] = xxteaKey;
                    data = decrypted;

                    var decPath = Path.Combine(outputDir, Path.GetFileName(filePath) + ".decrypted");
                    File.WriteAllBytes(decPath, data);
                    result.ExtractedFiles.Add(decPath);
                }
                else
                {
                    result.Warnings.Add("XXTEA decryption produced no valid Lua output - wrong key?");
                }
            }

            var format = DetectLuaFormat(data);
            result.Metadata["Format"] = format;

            switch (format)
            {
                case "PlainText":
                    ProcessPlainText(data, filePath, outputDir, result);
                    break;
                case "Bytecode":
                    ProcessBytecode(data, filePath, outputDir, result);
                    break;
                default:
                    result.Warnings.Add("Không xác định được định dạng");
                    var outPath = Path.Combine(outputDir, Path.GetFileName(filePath));
                    File.WriteAllBytes(outPath, data);
                    result.ExtractedFiles.Add(outPath);
                    break;
            }

            result.Success = true;
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Lỗi xử lý Lua: {ex.Message}");
            result.Success = false;
        }

        return result;
    }

    private static bool IsValidLuaData(byte[] data)
    {
        if (data == null || data.Length < 4)
            return false;

        // Lua bytecode signature
        if (data[0] == 0x1B && data[1] == 0x4C && data[2] == 0x75 && data[3] == 0x61)
            return true;

        // Check if valid UTF-8 text with Lua-like content
        try
        {
            var sample = System.Text.Encoding.UTF8.GetString(data, 0, Math.Min(512, data.Length));
            var asciiPrintable = sample.Count(c => c >= 32 && c <= 126 || c == 10 || c == 13 || c == 9);
            var replacementChars = sample.Count(c => c == 0xFFFD);
            if (replacementChars > sample.Length * 0.1)
                return false;
            if (asciiPrintable < sample.Length * 0.6)
                return false;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string DetectLuaFormat(byte[] data)
    {
        if (data.Length >= 4 &&
            data[0] == LuaSig[0] && data[1] == LuaSig[1] &&
            data[2] == LuaSig[2] && data[3] == LuaSig[3])
            return "Bytecode";

        var textSample = System.Text.Encoding.UTF8.GetString(data.Take(Math.Min(512, data.Length)).ToArray());
        if (textSample.Any(c => c < 32 && c != 10 && c != 13 && c != 9 && c != 0))
            return "Bytecode";

        return "PlainText";
    }

    private static void ProcessPlainText(byte[] data, string filePath, string outputDir, DecodeResult result)
    {
        var content = System.Text.Encoding.UTF8.GetString(data);
        var lines = content.Split('\n');
        var fileName = Path.GetFileName(filePath);
        var nameOnly = Path.GetFileNameWithoutExtension(fileName);

        result.Metadata["LineCount"] = lines.Length;
        result.Metadata["CharCount"] = content.Length;

        var obfuscated = DetectObfuscation(content, lines);
        result.Metadata["Obfuscated"] = obfuscated;

        var outPath = Path.Combine(outputDir, fileName);
        File.WriteAllText(outPath, content);
        result.ExtractedFiles.Add(outPath);

        var reportLines = new List<string>
        {
            $"=== Lua Script Report: {fileName} ===",
            $"Lines: {lines.Length}",
            $"Size: {content.Length} chars",
            $"Obfuscated: {obfuscated}",
            "",
        };

        ExtractApiUsage(content, result, reportLines);

        if (obfuscated)
        {
            reportLines.Add("");
            reportLines.Add("=== OBFUSCATION DETECTED ===");
            var deobfuscated = TryDeobfuscate(content);
            if (deobfuscated != content)
            {
                reportLines.Add("-> Auto-deobfuscated version saved");
                var deobPath = Path.Combine(outputDir, nameOnly + "_deobfuscated.lua");
                File.WriteAllText(deobPath, deobfuscated);
                result.ExtractedFiles.Add(deobPath);
            }

            reportLines.Add("-> Suspicious patterns found:");
            var suspiciousCount = 0;
            foreach (var line in lines)
            {
                var t = line.Trim();
                if (t.Contains("loadstring") || t.Contains("string.byte") ||
                    t.Contains("string.char") || t.Contains("rawget") ||
                    t.Contains("rawset") || t.Contains("getfenv"))
                {
                    suspiciousCount++;
                    reportLines.Add($"  L{Array.IndexOf(lines, line) + 1}: {Truncate(t, 80)}");
                }
            }
            reportLines.Add($"  Total suspicious lines: {suspiciousCount}");

            var deobfuscatedContent = TryDeobfuscate(content);
            if (deobfuscatedContent != content)
            {
                reportLines.Add("");
                reportLines.Add("=== DEOBFUSCATED CODE ===");
                reportLines.Add(deobfuscatedContent);
            }
        }

        GenerateStructure(lines, reportLines);

        var reportPath = Path.Combine(outputDir, nameOnly + "_report.txt");
        File.WriteAllLines(reportPath, reportLines);
        result.ExtractedFiles.Add(reportPath);
        result.Metadata["ReportFile"] = reportPath;
    }

    private static void ProcessBytecode(byte[] raw, string filePath, string outputDir, DecodeResult result)
    {
        var fileName = Path.GetFileName(filePath);
        var nameOnly = Path.GetFileNameWithoutExtension(fileName);
        var luaVersion = raw.Length > 5 ? raw[4] : (byte)0;
        result.Metadata["Size"] = FormatSize(raw.Length);

        var versionStr = luaVersion switch
        {
            0x50 => "Lua 5.0",
            0x51 => "Lua 5.1",
            0x52 => "Lua 5.2",
            0x53 => "Lua 5.3",
            0x54 => "Lua 5.4",
            _ => $"Lua (0x{luaVersion:X2})"
        };

        result.Metadata["LuaVersion"] = versionStr;
        result.Metadata["BytecodeSize"] = raw.Length;
        result.Metadata["Header"] = BitConverter.ToString(raw.Take(12).ToArray());

        var reportPath = Path.Combine(outputDir, nameOnly + "_bytecode_info.txt");
        var reportLines = new List<string>
        {
            $"=== Compiled Lua Bytecode: {fileName} ===",
            $"Version: {versionStr}",
            $"Size: {raw.Length} bytes",
            $"Header hex: {BitConverter.ToString(raw.Take(12).ToArray())}",
            "",
            "File này là Lua bytecode đã biên dịch, KHÔNG phải plain text.",
            "",
            "Để decompile, dùng các tool sau:",
            $"  - luadec (https://github.com/viruscamp/luadec) - cho {versionStr}",
            $"  - unluac (https://sourceforge.net/projects/unluac/) - cho Lua 5.1+",
            "  - luajit - nếu là LuaJIT bytecode",
            "",
            "Hướng dẫn:",
            $"  luadec \"{fileName}\" > \"{nameOnly}_decompiled.lua\"",
        };

        File.WriteAllLines(reportPath, reportLines);
        result.ExtractedFiles.Add(reportPath);

        var outPath = Path.Combine(outputDir, fileName);
        File.WriteAllBytes(outPath, raw);
        result.ExtractedFiles.Add(outPath);
    }

    private static bool DetectObfuscation(string content, string[] lines)
    {
        var minified = !content.Contains('\n') && content.Length > 500;
        var fewLines = lines.Length <= 3 && content.Length > 300;
        var hasLoadstring = content.Contains("loadstring", StringComparison.OrdinalIgnoreCase);
        var hasStringByte = content.Contains("string.byte", StringComparison.OrdinalIgnoreCase);
        var hasStringChar = content.Contains("string.char", StringComparison.OrdinalIgnoreCase);
        var hasRawget = content.Contains("rawget", StringComparison.OrdinalIgnoreCase);
        var hasGsub = content.Contains("gsub", StringComparison.OrdinalIgnoreCase);

        var score = (minified ? 2 : 0) + (fewLines ? 2 : 0) +
                    (hasLoadstring ? 3 : 0) + (hasStringByte ? 1 : 0) +
                    (hasStringChar ? 1 : 0) + (hasRawget ? 1 : 0) +
                    (hasGsub ? 1 : 0);

        return score >= 3;
    }

    private static string TryDeobfuscate(string content)
    {
        if (content.Contains('\n') || content.Length <= 1000)
            return content;

        var sb = new System.Text.StringBuilder();
        int indent = 0;
        bool inString = false;
        char stringChar = '"';

        for (int i = 0; i < content.Length; i++)
        {
            var c = content[i];

            if (inString)
            {
                sb.Append(c);
                if (c == '\\' && i + 1 < content.Length)
                    sb.Append(content[++i]);
                else if (c == stringChar)
                    inString = false;
                continue;
            }

            if (c == '"' || c == '\'')
            {
                inString = true;
                stringChar = c;
                sb.Append(c);
                continue;
            }

            if (c == '{')
            {
                indent++;
                sb.AppendLine(" {");
                sb.Append(new string(' ', indent * 2));
                continue;
            }

            if (c == '}')
            {
                indent = Math.Max(0, indent - 1);
                sb.AppendLine();
                sb.Append(new string(' ', indent * 2));
                sb.Append('}');
                if (i + 1 < content.Length && content[i + 1] == ',')
                {
                    sb.Append(',');
                    i++;
                }
                continue;
            }

            if (c == ';')
            {
                sb.AppendLine(";");
                sb.Append(new string(' ', indent * 2));
                continue;
            }

            if (c == ',')
            {
                sb.Append(", ");
                continue;
            }

            if (c == '=' && i + 1 < content.Length && content[i + 1] == '=')
            {
                sb.Append(" == ");
                i++;
                continue;
            }

            if (c == '~' && i + 1 < content.Length && content[i + 1] == '=')
            {
                sb.Append(" ~= ");
                i++;
                continue;
            }

            if (c == '<' && i + 1 < content.Length && content[i + 1] == '=')
            {
                sb.Append(" <= ");
                i++;
                continue;
            }

            if (c == '>' && i + 1 < content.Length && content[i + 1] == '=')
            {
                sb.Append(" >= ");
                i++;
                continue;
            }

            sb.Append(c);
        }

        return sb.ToString();
    }

    private static void ExtractApiUsage(string content, DecodeResult result, List<string> reportLines)
    {
        var matches = System.Text.RegularExpressions.Regex.Matches(content, @"(\w[\w._]*):(\w[\w_]*)\s*\(");

        var apiCalls = matches
            .Select(m => $"{m.Groups[1].Value}:{m.Groups[2].Value}")
            .Distinct()
            .OrderBy(x => x)
            .ToList();

        if (apiCalls.Count > 0)
        {
            var grouped = apiCalls
                .Select(a => a.Split(':')[0])
                .GroupBy(x => x)
                .OrderByDescending(g => g.Count())
                .ToList();

            reportLines.Add("=== MiniWorld API Calls Found ===");
            foreach (var g in grouped)
            {
                reportLines.Add($"  {g.Key}: {g.Count()} methods");
                foreach (var api in apiCalls.Where(a => a.StartsWith(g.Key + ":")))
                    reportLines.Add($"    - {api}");
            }

            result.Metadata["APIMethods"] = apiCalls.Count;
            result.Metadata["APIServices"] = grouped.Count;
            result.Metadata["APIList"] = string.Join(", ", apiCalls.Take(20));
            if (apiCalls.Count > 20)
                result.Metadata["APIList"] += $" ... (+{apiCalls.Count - 20} more)";
        }
        else
        {
            reportLines.Add("(Không tìm thấy API call MiniWorld)");
            result.Metadata["APIMethods"] = 0;
        }
    }

    private static void GenerateStructure(string[] lines, List<string> reportLines)
    {
        reportLines.Add("");
        reportLines.Add("=== Code Structure ===");

        var functions = new List<(int Line, string Name)>();
        var events = new List<string>();

        for (int i = 0; i < lines.Length; i++)
        {
            var t = lines[i].Trim();
            if (t.StartsWith("function ") || t.StartsWith("local function "))
                functions.Add((i + 1, t));
            if (t.Contains("ScriptSupportEvent:registerEvent"))
            {
                var match = System.Text.RegularExpressions.Regex.Match(t, @"\[=\[(.*?)\]=]");
                if (match.Success)
                    events.Add($"  L{i + 1}: Event '{match.Groups[1].Value}'");
            }
        }

        reportLines.Add($"Functions: {functions.Count}");
        foreach (var (line, name) in functions.Take(20))
            reportLines.Add($"  L{line}: {Truncate(name, 80)}");
        if (functions.Count > 20)
            reportLines.Add($"  ... (+{functions.Count - 20} more)");

        if (events.Count > 0)
        {
            reportLines.Add($"");
            reportLines.Add($"Registered Events ({events.Count}):");
            reportLines.AddRange(events);
        }
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "...";

    private static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
        < 1024 * 1024 * 1024 => $"{bytes / (1024.0 * 1024):F1} MB",
        _ => $"{bytes / (1024.0 * 1024 * 1024):F1} GB"
    };

    public static bool IsLuaFile(string path)
    {
        var ext = Path.GetExtension(path).ToLower();
        return ext is ".lua" or ".luac" or ".wsc";
    }
}
