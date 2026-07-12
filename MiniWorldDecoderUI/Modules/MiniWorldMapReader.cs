using MiniWorldDecoder.Models;

namespace MiniWorldDecoder.Modules;

public class MiniWorldMapReader
{
    public DecodeResult Decode(string directoryPath, string outputDir)
    {
        var result = new DecodeResult
        {
            FilePath = directoryPath,
            FileType = "MiniWorld Map",
        };

        try
        {
            var mapInfo = new MapInfo
            {
                FilePath = directoryPath
            };

            Directory.CreateDirectory(outputDir);

            var m0Dir = Path.Combine(directoryPath, "m0");
            if (Directory.Exists(m0Dir))
            {
                result.Metadata["ChunkDir"] = "m0";
                var regionFiles = Directory.GetFiles(m0Dir, "*.r");
                result.Metadata["RegionFileCount"] = regionFiles.Length;
                mapInfo.ChunkCount = regionFiles.Length;

                foreach (var regionFile in regionFiles)
                {
                    var rel = Path.GetRelativePath(directoryPath, regionFile);
                    var outPath = Path.Combine(outputDir, rel);
                    Directory.CreateDirectory(Path.GetDirectoryName(outPath)!);
                    File.Copy(regionFile, outPath, true);
                    result.ExtractedFiles.Add(outPath);

                    var regionResult = ParseRegionFile(regionFile);
                    if (regionResult != null)
                    {
                        mapInfo.BlockCount += regionResult.Value.BlockCount;
                    }
                }
            }

            var assetDir = Path.Combine(directoryPath, "sandbox", "assets");
            if (Directory.Exists(assetDir))
            {
                result.Metadata["HasSandboxAssets"] = true;
                CopyDirectory(assetDir, Path.Combine(outputDir, "sandbox", "assets"), result);
            }

            var dataDir = Path.Combine(directoryPath, "data");
            if (Directory.Exists(dataDir))
            {
                CopyDirectory(dataDir, Path.Combine(outputDir, "data"), result);
            }

            var sandboxDir = Path.Combine(directoryPath, "sandbox");
            if (Directory.Exists(sandboxDir))
            {
                CopyDirectory(sandboxDir, Path.Combine(outputDir, "sandbox"), result);
            }

            var pluginDir = Path.Combine(directoryPath, "plugin");
            if (Directory.Exists(pluginDir))
            {
                result.Metadata["HasPlugins"] = true;
                CopyDirectory(pluginDir, Path.Combine(outputDir, "plugin"), result);
            }

            var scriptLog = Path.Combine(directoryPath, "ss", "TriggerScript.log");
            if (File.Exists(scriptLog))
            {
                var logOut = Path.Combine(outputDir, "TriggerScript.log");
                File.Copy(scriptLog, logOut, true);
                result.ExtractedFiles.Add(logOut);
            }

            foreach (var iniFile in Directory.GetFiles(directoryPath, "*.ini", SearchOption.TopDirectoryOnly))
            {
                var outPath = Path.Combine(outputDir, Path.GetFileName(iniFile));
                File.Copy(iniFile, outPath, true);
                result.ExtractedFiles.Add(outPath);
                ParseIniFile(iniFile, mapInfo, result);
            }

            foreach (var txtFile in Directory.GetFiles(directoryPath, "*.txt", SearchOption.TopDirectoryOnly))
            {
                var outPath = Path.Combine(outputDir, Path.GetFileName(txtFile));
                File.Copy(txtFile, outPath, true);
                result.ExtractedFiles.Add(outPath);
            }

            var infoPath = Path.Combine(outputDir, "map_info.json");
            var mapInfoJson = System.Text.Json.JsonSerializer.Serialize(mapInfo, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(infoPath, mapInfoJson);
            result.ExtractedFiles.Add(infoPath);

            result.Metadata["MapInfo"] = mapInfo;
            result.Success = true;
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Error reading map: {ex.Message}");
            result.Success = false;
        }

        return result;
    }

    private (int BlockCount, int ChunkVersion)? ParseRegionFile(string filePath)
    {
        try
        {
            using var fs = File.OpenRead(filePath);
            using var br = new BinaryReader(fs);

            if (fs.Length < 4) return null;

            var magic = br.ReadInt32();
            int blockCount = 0;

            if (magic == 0x524F4F4D || magic == 0x4F4F4D52)
            {
                var version = br.ReadInt32();
                var chunkCount = br.ReadInt32();

                for (int i = 0; i < Math.Min(chunkCount, 1024); i++)
                {
                    var offset = br.ReadInt32();
                    var size = br.ReadInt32();
                    if (offset > 0 && size > 0)
                    {
                        blockCount += size / 8;
                    }
                }
                return (blockCount, version);
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private void ParseIniFile(string iniPath, MapInfo mapInfo, DecodeResult result)
    {
        try
        {
            foreach (var line in File.ReadAllLines(iniPath))
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith('[') || trimmed.StartsWith(';') || trimmed.StartsWith('#'))
                    continue;

                var eqIdx = trimmed.IndexOf('=');
                if (eqIdx < 0) continue;

                var key = trimmed[..eqIdx].Trim().ToLower();
                var value = trimmed[(eqIdx + 1)..].Trim();

                mapInfo.Properties[key] = value;

                switch (key)
                {
                    case "game_mode":
                    case "gamemode":
                        mapInfo.GameMode = value;
                        break;
                    case "seed":
                        if (long.TryParse(value, out var seed))
                            mapInfo.Seed = seed;
                        break;
                    case "world_width":
                    case "width":
                        if (int.TryParse(value, out var w)) mapInfo.WorldWidth = w;
                        break;
                    case "world_height":
                    case "height":
                        if (int.TryParse(value, out var h)) mapInfo.WorldHeight = h;
                        break;
                    case "world_depth":
                    case "depth":
                        if (int.TryParse(value, out var d)) mapInfo.WorldDepth = d;
                        break;
                    case "version":
                        if (int.TryParse(value, out var v)) mapInfo.Version = v;
                        break;
                    case "plugin":
                    case "plugins":
                        mapInfo.PluginsUsed.Add(value);
                        break;
                }
            }
        }
        catch
        {
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

    public static bool IsMiniWorldMap(string path)
    {
        if (!Directory.Exists(path)) return false;

        if (Directory.Exists(Path.Combine(path, "m0")) &&
            Directory.GetFiles(Path.Combine(path, "m0"), "*.r").Length > 0)
            return true;

        if (Directory.Exists(Path.Combine(path, "sandbox")))
            return true;

        return false;
    }
}
