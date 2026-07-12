namespace MiniWorldDecoder.Models;

public class MapInfo
{
    public string FilePath { get; set; } = "";
    public long FileSize { get; set; }
    public int Version { get; set; }
    public long Seed { get; set; }
    public int WorldWidth { get; set; }
    public int WorldHeight { get; set; }
    public int WorldDepth { get; set; }
    public string GameMode { get; set; } = "";
    public int ChunkCount { get; set; }
    public int BlockCount { get; set; }
    public List<string> PluginsUsed { get; set; } = new();
    public Dictionary<string, string> Properties { get; set; } = new();
}
