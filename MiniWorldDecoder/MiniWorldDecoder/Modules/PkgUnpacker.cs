using System.IO.Compression;
using MiniWorldDecoder.Models;

namespace MiniWorldDecoder.Modules;

public class PkgUnpacker
{
    private static readonly byte[] ZipMagic = { 0x50, 0x4B, 0x03, 0x04 };
    private static readonly byte[] ZipEmptyMagic = { 0x50, 0x4B, 0x05, 0x06 };
    private static readonly byte[] ZipSpanMagic = { 0x50, 0x4B, 0x07, 0x08 };

    public DecodeResult Decode(string filePath, string outputDir)
    {
        var result = new DecodeResult
        {
            FilePath = filePath,
            FileType = "PKG Resource Pack",
            FileSize = new FileInfo(filePath).Length
        };

        try
        {
            var rawData = File.ReadAllBytes(filePath);
            var zipStart = FindZipStart(rawData);
            Directory.CreateDirectory(outputDir);

            if (zipStart >= 0)
            {
                var zipData = rawData;
                if (zipStart > 0)
                {
                    zipData = rawData.Skip(zipStart).ToArray();
                    result.Metadata["HeaderSkipped"] = zipStart;
                    result.Metadata["OriginalHeader"] = BitConverter.ToString(rawData.Take(Math.Min(zipStart, 32)).ToArray());
                    result.Warnings.Add($"Đã bỏ qua {zipStart} bytes header tùy chỉnh trước dữ liệu ZIP");
                }

                var tempZip = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.zip");
                try
                {
                    File.WriteAllBytes(tempZip, zipData);

                    try
                    {
                        ZipFile.ExtractToDirectory(tempZip, outputDir, overwriteFiles: true);
                        result.ExtractedFiles.AddRange(Directory.GetFiles(outputDir, "*", SearchOption.AllDirectories));
                        result.Metadata["ExtractionMethod"] = "ZIP (standard)";
                        result.Success = true;
                    }
                    catch (InvalidDataException)
                    {
                        result.Warnings.Add("ZIP thường không hoạt động, thử chế độ nén raw...");
                        var altExtracted = TryExtractZlibRaw(rawData, outputDir);
                        if (altExtracted.Count > 0)
                        {
                            result.ExtractedFiles = altExtracted;
                            result.Metadata["ExtractionMethod"] = "zlib raw";
                            result.Success = true;
                        }
                        else
                        {
                            result.Errors.Add("Không thể giải nén - định dạng không xác định");
                            result.Success = false;
                        }
                    }
                }
                finally
                {
                    if (File.Exists(tempZip)) File.Delete(tempZip);
                }
            }
            else
            {
                result.Warnings.Add("Không tìm thấy magic bytes ZIP, thử giải nén raw zlib...");
                var extracted = TryExtractZlibRaw(rawData, outputDir);

                if (extracted.Count > 0)
                {
                    result.ExtractedFiles = extracted;
                    result.Metadata["ExtractionMethod"] = "zlib raw (no ZIP)";
                    result.Success = true;
                }
                else
                {
                    result.Errors.Add("Không tìm thấy cấu trúc ZIP hoặc zlib trong file");
                    result.Success = false;
                }
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Lỗi: {ex.Message}");
            result.Success = false;
        }

        if (result.Success && result.ExtractedFiles.Count > 0)
        {
            var totalBytes = result.ExtractedFiles.Sum(f =>
            {
                try { return new FileInfo(f).Length; }
                catch { return 0L; }
            });
            result.Metadata["TotalExtractedBytes"] = FormatSize(totalBytes);
        }

        return result;
    }

    private static int FindZipStart(byte[] data)
    {
        if (data.Length < 4) return -1;

        for (int i = 0; i <= data.Length - 4; i++)
        {
            if (data[i] == 0x50 && data[i + 1] == 0x4B &&
                (data[i + 2] == 0x03 || data[i + 2] == 0x05 || data[i + 2] == 0x07) &&
                data[i + 3] == 0x04)
                return i;
        }

        return -1;
    }

    private static List<string> TryExtractZlibRaw(byte[] data, string outputDir)
    {
        var extracted = new List<string>();
        Directory.CreateDirectory(outputDir);
        int fileIndex = 0;

        for (int i = 0; i < data.Length - 2; i++)
        {
            if (data[i] != 0x78) continue;
            if (data[i + 1] != 0x01 && data[i + 1] != 0x5E &&
                data[i + 1] != 0x9C && data[i + 1] != 0xDA) continue;

            try
            {
                using var ms = new MemoryStream(data, i, data.Length - i);
                using var deflate = new DeflateStream(ms, CompressionMode.Decompress);
                using var outMs = new MemoryStream();
                deflate.CopyTo(outMs);
                var decompressed = outMs.ToArray();

                if (decompressed.Length > 64)
                {
                    var ext = DetectFileExtension(decompressed);
                    var name = $"extracted_{fileIndex:D4}{ext}";
                    var outPath = Path.Combine(outputDir, name);
                    File.WriteAllBytes(outPath, decompressed);
                    extracted.Add(outPath);
                    fileIndex++;
                }
            }
            catch
            {
            }
        }

        return extracted;
    }

    private static string DetectFileExtension(byte[] data)
    {
        if (data.Length < 4) return ".bin";

        if (data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47) return ".png";
        if (data[0] == 0xFF && data[1] == 0xD8) return ".jpg";
        if (data[0] == 0x47 && data[1] == 0x49 && data[2] == 0x46) return ".gif";
        if (data[0] == 0x52 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x46) return ".wav";
        if (data[0] == 0x4F && data[1] == 0x67 && data[2] == 0x67 && data[3] == 0x53) return ".ogg";
        if (data[0] == 0x66 && data[1] == 0x74 && data[2] == 0x79 && data[3] == 0x70) return ".mp4";
        if (data[0] == 0x1B && data[1] == 0x4C && data[2] == 0x75) return ".lua";
        if (data[0] == 0x7B) return ".json";
        if (data[0] == 0x3C) return data.Length > 1 && data[1] == 0x3F ? ".xml" : ".html";
        if (data[0] == 0x4D && data[1] == 0x53 && data[2] == 0x43 && data[3] == 0x46) return ".bytes";
        if (data[0] == 0xD0 && data[1] == 0xCF) return ".dll";
        if (data[0] == 0x4D && data[1] == 0x5A) return ".exe";
        if (data[0] == 0x25 && data[1] == 0x50 && data[2] == 0x44 && data[3] == 0x46) return ".pdf";

        try
        {
            var textSample = System.Text.Encoding.UTF8.GetString(data.Take(128).ToArray());
            if (textSample.All(c => c >= 32 || c == 10 || c == 13 || c == 9))
                return ".txt";
        }
        catch { }

        return ".bin";
    }

    private static string FormatSize(long bytes)
    {
        return bytes switch
        {
            < 1024 => $"{bytes} B",
            < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
            < 1024 * 1024 * 1024 => $"{bytes / (1024.0 * 1024):F1} MB",
            _ => $"{bytes / (1024.0 * 1024 * 1024):F1} GB"
        };
    }

    public static bool IsPkgFile(string filePath)
    {
        try
        {
            var data = File.ReadAllBytes(filePath);
            return FindZipStart(data) >= 0;
        }
        catch
        {
            return false;
        }
    }
}
