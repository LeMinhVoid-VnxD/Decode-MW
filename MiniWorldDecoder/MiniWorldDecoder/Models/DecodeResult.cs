namespace MiniWorldDecoder.Models;

public class DecodeResult
{
    public bool Success { get; set; }
    public string FilePath { get; set; } = "";
    public string FileType { get; set; } = "";
    public long FileSize { get; set; }
    public List<string> ExtractedFiles { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
    public List<string> Errors { get; set; } = new();
    public Dictionary<string, object> Metadata { get; set; } = new();
}
