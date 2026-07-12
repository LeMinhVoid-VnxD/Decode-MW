namespace MiniWorldDecoder.Models;

public class SecurityIssue
{
    public string File { get; set; } = "";
    public int Line { get; set; }
    public SeverityLevel Severity { get; set; }
    public string Category { get; set; } = "";
    public string Description { get; set; } = "";
    public string Code { get; set; } = "";
    public string Recommendation { get; set; } = "";
}

public enum SeverityLevel
{
    Info,
    Low,
    Medium,
    High,
    Critical
}
