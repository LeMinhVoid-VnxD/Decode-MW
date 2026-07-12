using System.Text.RegularExpressions;
using MiniWorldDecoder.Models;

namespace MiniWorldDecoder.Modules;

public class SecurityAnalyzer
{
    private static readonly Dictionary<string, string[]> DangerousPatterns = new()
    {
        ["FileSystemAccess"] = new[]
        {
            @"io\.(open|read|write|popen|lines?)",
            @"os\.execute",
            @"os\.rename",
            @"os\.remove",
            @"os\.exit",
            @"os\.tmpname",
            @"lfs\.",
            @"require\s*[\(]",
            @"loadfile",
            @"dofile",
        },
        ["NetworkAccess"] = new[]
        {
            @"socket\.(connect|tcp|udp)",
            @"http\.request",
            @"https?://",
            @"request\s*[\(]",
            @"WebService",
            @"HttpService",
        },
        ["CodeExecution"] = new[]
        {
            @"loadstring",
            @"load",
            @"assert\s*\(load",
            @"setfenv",
            @"getfenv",
            @"newproxy",
            @"rawget",
            @"rawset",
            @"debug\.",
        },
        ["DataExfiltration"] = new[]
        {
            @"print\s*\(.*(?:player|account|token|password|passwd|pwd|cookie|session)",
            @"Chat:sendSystemMsg\s*\(.*(?:account|token|password|cookie)",
            @"sendLog\s*\(.*(?:account|token|password)",
        },
        ["SuspiciousAPI"] = new[]
        {
            @"os\.clock",
            @"os\.difftime",
            @"os\.time",
            @"os\.date",
            @"collectgarbage",
            @"gcinfo",
        },
        ["PluginAbuse"] = new[]
        {
            @"VarLib2:setPlayerVarByName",
            @"VarLib2:setGlobalVarByName",
            @"ScriptSupportEvent:registerEvent",
            @"World:getAllPlayers",
            @"Player:kick",
            @"Player:ban",
            @"Player:getUserId",
            @"Player:getAccountId",
        },
    };

    public DecodeResult AnalyzeDirectory(string directoryPath)
    {
        var result = new DecodeResult
        {
            FilePath = directoryPath,
            FileType = "Security Analysis"
        };

        try
        {
            var issues = new List<SecurityIssue>();

            var luaFiles = Directory.GetFiles(directoryPath, "*.lua", SearchOption.AllDirectories);
            var jsonFiles = Directory.GetFiles(directoryPath, "*.json", SearchOption.AllDirectories);
            var txtFiles = Directory.GetFiles(directoryPath, "*.txt", SearchOption.AllDirectories);

            foreach (var file in luaFiles)
                AnalyzeLuaFile(file, issues);

            foreach (var file in jsonFiles)
                AnalyzeJsonFile(file, issues);

            foreach (var file in txtFiles)
                AnalyzeTextFile(file, issues);

            result.Metadata["TotalIssues"] = issues.Count;
            result.Metadata["IssuesBySeverity"] = issues
                .GroupBy(i => i.Severity)
                .ToDictionary(g => g.Key.ToString(), g => g.Count());

            if (issues.Count > 0)
            {
                var issuesPath = Path.Combine(directoryPath, "..", "security_report.json");
                issuesPath = Path.GetFullPath(issuesPath);

                var report = new
                {
                    AnalysisDate = DateTime.UtcNow,
                    TotalIssues = issues.Count,
                    Summary = new
                    {
                        Critical = issues.Count(i => i.Severity == SeverityLevel.Critical),
                        High = issues.Count(i => i.Severity == SeverityLevel.High),
                        Medium = issues.Count(i => i.Severity == SeverityLevel.Medium),
                        Low = issues.Count(i => i.Severity == SeverityLevel.Low),
                        Info = issues.Count(i => i.Severity == SeverityLevel.Info),
                    },
                    Issues = issues.OrderByDescending(i => i.Severity).ThenBy(i => i.File),
                };

                var reportJson = System.Text.Json.JsonSerializer.Serialize(report,
                    new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(issuesPath, reportJson);
                result.Metadata["ReportPath"] = issuesPath;
                result.ExtractedFiles.Add(issuesPath);
            }

            result.Success = true;
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Security analysis error: {ex.Message}");
            result.Success = false;
        }

        return result;
    }

    private void AnalyzeLuaFile(string filePath, List<SecurityIssue> issues)
    {
        var lines = File.ReadAllLines(filePath);
        var fileName = Path.GetRelativePath(Directory.GetCurrentDirectory(), filePath);

        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var trimmed = line.Trim();

            if (trimmed.StartsWith("--") || trimmed.StartsWith("//"))
                continue;

            foreach (var (category, patterns) in DangerousPatterns)
            {
                foreach (var pattern in patterns)
                {
                    var match = Regex.Match(trimmed, pattern, RegexOptions.IgnoreCase);
                    if (!match.Success) continue;

                    var severity = category switch
                    {
                        "FileSystemAccess" => SeverityLevel.High,
                        "NetworkAccess" => SeverityLevel.High,
                        "CodeExecution" => SeverityLevel.Critical,
                        "DataExfiltration" => SeverityLevel.Critical,
                        "SuspiciousAPI" => SeverityLevel.Medium,
                        "PluginAbuse" => SeverityLevel.Medium,
                        _ => SeverityLevel.Low,
                    };

                    var description = category switch
                    {
                        "FileSystemAccess" => "File system access detected - may read/write files outside sandbox",
                        "NetworkAccess" => "Network access detected - may communicate with external servers",
                        "CodeExecution" => "Dynamic code execution detected - potential code injection risk",
                        "DataExfiltration" => "Possible data exfiltration - sensitive data being output",
                        "SuspiciousAPI" => "Use of timing/performance APIs - potential fingerprinting",
                        "PluginAbuse" => "Plugin API abuse - may affect other players' game state",
                        _ => $"Suspicious pattern detected in category: {category}",
                    };

                    issues.Add(new SecurityIssue
                    {
                        File = fileName,
                        Line = i + 1,
                        Severity = severity,
                        Category = category,
                        Description = description,
                        Code = trimmed.Length > 100 ? trimmed[..100] + "..." : trimmed,
                        Recommendation = category switch
                        {
                            "FileSystemAccess" => "Restrict file I/O operations in plugin scripts",
                            "NetworkAccess" => "Block unauthorized network connections",
                            "CodeExecution" => "Remove dynamic code execution (loadstring/load)",
                            "DataExfiltration" => "Audit data output/logging for sensitive information",
                            "PluginAbuse" => "Review plugin API usage for fair play compliance",
                            _ => "Review and validate this code pattern",
                        },
                    });

                    break;
                }
            }
        }

        var totalLines = lines.Length;
        if (totalLines > 500)
        {
            issues.Add(new SecurityIssue
            {
                File = fileName,
                Line = 1,
                Severity = SeverityLevel.Info,
                Category = "FileSize",
                Description = $"Large script file ({totalLines} lines) - may contain obfuscated code",
                Code = $"Total lines: {totalLines}",
                Recommendation = "Review large script files for obfuscation or malicious code"
            });
        }
    }

    private void AnalyzeJsonFile(string filePath, List<SecurityIssue> issues)
    {
        var text = File.ReadAllText(filePath);
        var fileName = Path.GetRelativePath(Directory.GetCurrentDirectory(), filePath);

        if (text.Contains("loadstring", StringComparison.OrdinalIgnoreCase))
        {
            issues.Add(new SecurityIssue
            {
                File = fileName,
                Line = 1,
                Severity = SeverityLevel.Critical,
                Category = "CodeExecution",
                Description = "JSON contains loadstring reference - potential obfuscated code injection",
                Code = "Contains 'loadstring'",
                Recommendation = "Remove loadstring from JSON resources"
            });
        }

        if (text.Contains("http://", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("https://", StringComparison.OrdinalIgnoreCase))
        {
            issues.Add(new SecurityIssue
            {
                File = fileName,
                Line = 1,
                Severity = SeverityLevel.Medium,
                Category = "NetworkAccess",
                Description = "JSON contains URL references - may download external content",
                Code = "Contains URL reference",
                Recommendation = "Verify external URL references are safe"
            });
        }

        if (text.Length > 100_000 && !text.Contains("\n"))
        {
            issues.Add(new SecurityIssue
            {
                File = fileName,
                Line = 1,
                Severity = SeverityLevel.High,
                Category = "Obfuscation",
                Description = "Minified JSON over 100KB - possible obfuscated data",
                Code = $"Size: {text.Length} bytes",
                Recommendation = "Review large minified JSON files"
            });
        }
    }

    private void AnalyzeTextFile(string filePath, List<SecurityIssue> issues)
    {
        var fileName = Path.GetRelativePath(Directory.GetCurrentDirectory(), filePath);

        if (Path.GetFileName(filePath).Equals("TriggerScript.log", StringComparison.OrdinalIgnoreCase))
        {
            var lines = File.ReadAllLines(filePath);
            if (lines.Length > 0)
            {
                issues.Add(new SecurityIssue
                {
                    File = fileName,
                    Line = 1,
                    Severity = SeverityLevel.Info,
                    Category = "ScriptLog",
                    Description = $"Trigger script log contains {lines.Length} lines of output data",
                    Code = $"Total lines: {lines.Length}",
                    Recommendation = "Review logged data for sensitive information exposure"
                });
            }
        }
    }
}
