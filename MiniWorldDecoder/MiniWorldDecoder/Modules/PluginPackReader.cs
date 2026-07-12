using System.Text.Json;
using MiniWorldDecoder.Models;

namespace MiniWorldDecoder.Modules;

public class PluginPackReader
{
    public DecodeResult Decode(string directoryPath, string outputDir)
    {
        var result = new DecodeResult
        {
            FilePath = directoryPath,
            FileType = "MiniWorld Plugin Pack",
        };

        try
        {
            var manifestPath = Path.Combine(directoryPath, "pack_manifest.json");
            if (!File.Exists(manifestPath))
            {
                manifestPath = Directory.GetFiles(directoryPath, "pack_manifest.json", SearchOption.AllDirectories).FirstOrDefault() ?? "";
                if (string.IsNullOrEmpty(manifestPath))
                {
                    result.Errors.Add("pack_manifest.json not found");
                    result.Success = false;
                    return result;
                }
            }

            var json = File.ReadAllText(manifestPath);
            var info = ParseManifest(json);
            if (info != null)
            {
                result.Metadata["PackName"] = info.Name;
                result.Metadata["Author"] = info.Author;
                result.Metadata["Version"] = info.PackVersion;
                result.Metadata["API"] = info.ApiVersion;
                result.Metadata["UUID"] = info.Uuid;
                result.Metadata["ModType"] = info.ModType;
                result.Metadata["RawManifest"] = info.RawJson;
            }

            Directory.CreateDirectory(outputDir);

            var manifestOut = Path.Combine(outputDir, "pack_manifest.json");
            File.WriteAllText(manifestOut, json);
            result.ExtractedFiles.Add(manifestOut);

            var behaviorDir = Path.GetFullPath(Path.Combine(directoryPath, "behavior"));
            if (Directory.Exists(behaviorDir))
                CopyDirectory(behaviorDir, Path.Combine(outputDir, "behavior"), result);

            var resourceDir = Path.GetFullPath(Path.Combine(directoryPath, "resource"));
            if (Directory.Exists(resourceDir))
                CopyDirectory(resourceDir, Path.Combine(outputDir, "resource"), result);

            var logicalDir = Path.GetFullPath(Path.Combine(directoryPath, "logical"));
            if (Directory.Exists(logicalDir))
                CopyDirectory(logicalDir, Path.Combine(outputDir, "logical"), result);

            var luaFiles = Directory.GetFiles(directoryPath, "*.lua", SearchOption.AllDirectories);
            foreach (var lua in luaFiles)
            {
                var relPath = Path.GetRelativePath(directoryPath, lua);
                var outPath = Path.Combine(outputDir, relPath);
                Directory.CreateDirectory(Path.GetDirectoryName(outPath)!);
                File.Copy(lua, outPath, true);
                result.ExtractedFiles.Add(outPath);
            }

            result.Success = true;
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Error reading plugin pack: {ex.Message}");
            result.Success = false;
        }

        return result;
    }

    public static PluginPackInfo? ParseManifest(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var info = new PluginPackInfo
            {
                RawJson = json
            };

            if (root.TryGetProperty("name", out var name)) info.Name = name.GetString() ?? "";
            if (root.TryGetProperty("description", out var desc)) info.Description = desc.GetString() ?? "";
            if (root.TryGetProperty("author", out var author)) info.Author = author.GetString() ?? "";
            if (root.TryGetProperty("pack_version", out var pv)) info.PackVersion = pv.GetString() ?? "";
            if (root.TryGetProperty("api_version", out var av)) info.ApiVersion = av.GetString() ?? "";
            if (root.TryGetProperty("mod_type", out var mt)) info.ModType = mt.GetInt32();
            if (root.TryGetProperty("restart_required", out var rr)) info.RestartRequired = rr.GetBoolean();
            if (root.TryGetProperty("open_edit", out var oe)) info.OpenEdit = oe.GetBoolean();
            if (root.TryGetProperty("standalone", out var sa)) info.Standalone = sa.GetBoolean();
            if (root.TryGetProperty("uuid", out var uuid)) info.Uuid = uuid.GetString() ?? "";
            if (root.TryGetProperty("authoruin", out var au)) info.AuthorUin = au.GetInt64();
            if (root.TryGetProperty("author_head_iconindex", out var hi)) info.AuthorHeadIconIndex = hi.GetInt32();

            var localeSuffixes = new[] { "en", "tw", "tha", "esn", "ptb", "fra", "jpn", "ara", "kor", "vie", "idn" };
            foreach (var suffix in localeSuffixes)
            {
                if (root.TryGetProperty($"{suffix}_name", out var ln))
                    info.LocalizedNames[suffix] = ln.GetString() ?? "";
                if (root.TryGetProperty($"{suffix}_description", out var ld))
                    info.LocalizedDescriptions[suffix] = ld.GetString() ?? "";
                if (root.TryGetProperty($"{suffix}_author", out var la))
                    info.LocalizedAuthors[suffix] = la.GetString() ?? "";
            }

            return info;
        }
        catch
        {
            return null;
        }
    }

    private static void CopyDirectory(string source, string dest, DecodeResult result)
    {
        Directory.CreateDirectory(dest);
        foreach (var file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
        {
            var relPath = Path.GetRelativePath(source, file);
            var outPath = Path.Combine(dest, relPath);
            Directory.CreateDirectory(Path.GetDirectoryName(outPath)!);
            File.Copy(file, outPath, true);
            result.ExtractedFiles.Add(outPath);
        }
    }

    public static bool IsPluginPack(string path)
    {
        if (Directory.Exists(path))
            return File.Exists(Path.Combine(path, "pack_manifest.json"));

        if (File.Exists(path) && Path.GetExtension(path)?.ToLower() == ".zip")
            return true;

        return false;
    }
}
