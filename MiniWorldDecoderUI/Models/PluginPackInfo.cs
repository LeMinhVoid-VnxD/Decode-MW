namespace MiniWorldDecoder.Models;

public class PluginPackInfo
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public string Author { get; set; } = "";
    public string PackVersion { get; set; } = "";
    public string ApiVersion { get; set; } = "";
    public int ModType { get; set; }
    public bool RestartRequired { get; set; }
    public bool OpenEdit { get; set; }
    public bool Standalone { get; set; }
    public string Uuid { get; set; } = "";
    public long AuthorUin { get; set; }
    public int AuthorHeadIconIndex { get; set; }
    public Dictionary<string, string> LocalizedNames { get; set; } = new();
    public Dictionary<string, string> LocalizedDescriptions { get; set; } = new();
    public Dictionary<string, string> LocalizedAuthors { get; set; } = new();
    public string RawJson { get; set; } = "";
}
