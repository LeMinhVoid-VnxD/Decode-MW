using MiniWorldDecoder.Models;
using MiniWorldDecoder.Modules;

namespace MiniWorldDecoderUI;

public class MainForm : Form
{
    private Panel dropPanel;
    private Label lblDrop;
    private TextBox txtPath;
    private Button btnBrowse;
    private ComboBox cmbType;
    private TextBox txtKey;
    private Label lblKey;
    private Button btnDecode;
    private ProgressBar progressBar;
    private ListView lvFiles;
    private RichTextBox rtbLog;
    private Label lblStatus;
    private Label lblOutputPath;
    private Button btnOpenOutput;

    private DecodeResult? lastResult;
    private string? lastOutputDir;

    public MainForm()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        this.Text = "MiniWorld Decoder";
        this.Size = new Size(800, 650);
        this.MinimumSize = new Size(600, 450);
        this.StartPosition = FormStartPosition.CenterScreen;
        this.Font = new Font("Segoe UI", 9);
        this.BackColor = Color.WhiteSmoke;

        var lblTitle = new Label
        {
            Text = "MiniWorld Decoder",
            Font = new Font("Segoe UI", 16, FontStyle.Bold),
            ForeColor = Color.DarkBlue,
            Location = new Point(12, 9),
            Size = new Size(400, 30)
        };

        var lblSub = new Label
        {
            Text = "Decode .pkg, .lua, plugin pack, map MiniWorld",
            Font = new Font("Segoe UI", 9),
            ForeColor = Color.Gray,
            Location = new Point(15, 38),
            Size = new Size(500, 18)
        };

        // Drag-drop panel
        dropPanel = new Panel
        {
            Location = new Point(12, 65),
            Size = new Size(755, 80),
            BackColor = Color.FromArgb(240, 245, 255),
            BorderStyle = BorderStyle.FixedSingle,
            AllowDrop = true
        };

        lblDrop = new Label
        {
            Text = "Kéo thả file / thư mục vào đây",
            Font = new Font("Segoe UI", 10),
            ForeColor = Color.Gray,
            TextAlign = ContentAlignment.MiddleCenter,
            Location = new Point(0, 20),
            Size = dropPanel.Size,
            AutoSize = false
        };

        dropPanel.Paint += (s, e) =>
        {
            var r = dropPanel.ClientRectangle;
            r.Inflate(-3, -3);
            using var p = new Pen(Color.FromArgb(100, 150, 220), 1);
            p.DashStyle = System.Drawing.Drawing2D.DashStyle.Dash;
            e.Graphics.DrawRectangle(p, r);
        };

        dropPanel.Controls.Add(lblDrop);

        dropPanel.DragEnter += (s, e) =>
        {
            if (e.Data!.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effect = DragDropEffects.Copy;
                dropPanel.BackColor = Color.FromArgb(220, 235, 255);
            }
        };
        dropPanel.DragLeave += (s, e) => dropPanel.BackColor = Color.FromArgb(240, 245, 255);
        dropPanel.DragDrop += (s, e) =>
        {
            dropPanel.BackColor = Color.FromArgb(240, 245, 255);
            if (e.Data!.GetDataPresent(DataFormats.FileDrop))
            {
                var files = (string[])e.Data.GetData(DataFormats.FileDrop)!;
                if (files.Length > 0)
                {
                    txtPath.Text = files[0];
                    lblDrop.Text = Path.GetFileName(files[0]);
                }
            }
        };

        // Path
        txtPath = new TextBox
        {
            Location = new Point(12, 155),
            Size = new Size(640, 22),
        };
        txtPath.TextChanged += (s, e) =>
        {
            if (!string.IsNullOrEmpty(txtPath.Text))
            {
                try { lblDrop.Text = Path.GetFileName(txtPath.Text); }
                catch { lblDrop.Text = txtPath.Text; }
            }
            else lblDrop.Text = "Kéo thả file / thư mục vào đây";
        };

        btnBrowse = new Button
        {
            Text = "Browse",
            Location = new Point(660, 153),
            Size = new Size(107, 26),
            UseVisualStyleBackColor = true
        };
        btnBrowse.Click += (s, e) =>
        {
            using var dlg = new OpenFileDialog
            {
                Title = "Chọn file MiniWorld",
                Filter = "All supported (*.pkg;*.lua;*.luac;*.zip;*.miniworld)|*.pkg;*.lua;*.luac;*.zip;*.miniworld|All files (*.*)|*.*"
            };
            if (dlg.ShowDialog() == DialogResult.OK)
                txtPath.Text = dlg.FileName;
        };

        // Type + Decode
        cmbType = new ComboBox
        {
            Location = new Point(12, 188),
            Size = new Size(120, 21),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        cmbType.Items.AddRange(new[] { "auto", "pkg", "plugin", "map", "lua" });
        cmbType.SelectedIndex = 0;

        lblKey = new Label
        {
            Text = "Key XXTEA:",
            Location = new Point(140, 190),
            Size = new Size(70, 20),
            TextAlign = ContentAlignment.MiddleLeft
        };

        txtKey = new TextBox
        {
            Location = new Point(210, 189),
            Size = new Size(140, 22),
            ForeColor = Color.Gray,
            Text = "(nếu có)"
        };
        txtKey.GotFocus += (s, e) => { if (txtKey.Text == "(nếu có)") { txtKey.Text = ""; txtKey.ForeColor = Color.Black; } };
        txtKey.LostFocus += (s, e) => { if (string.IsNullOrEmpty(txtKey.Text)) { txtKey.Text = "(nếu có)"; txtKey.ForeColor = Color.Gray; } };

        btnDecode = new Button
        {
            Text = "DECODE",
            Location = new Point(365, 186),
            Size = new Size(120, 30),
            BackColor = Color.DodgerBlue,
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 9, FontStyle.Bold),
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand
        };
        btnDecode.Click += BtnDecode_Click;

        progressBar = new ProgressBar
        {
            Location = new Point(500, 190),
            Size = new Size(160, 22),
            Style = ProgressBarStyle.Marquee,
            Visible = false,
            MarqueeAnimationSpeed = 30
        };

        lblOutputPath = new Label
        {
            Location = new Point(670, 192),
            Size = new Size(100, 18),
            ForeColor = Color.Gray,
            Text = ""
        };

        // Status
        lblStatus = new Label
        {
            Location = new Point(12, 225),
            Size = new Size(755, 18),
            ForeColor = Color.Gray
        };

        btnOpenOutput = new Button
        {
            Text = "Mở thư mục output",
            Location = new Point(12, 570),
            Size = new Size(150, 28),
            Visible = false,
            UseVisualStyleBackColor = true
        };
        btnOpenOutput.Click += (s, e) =>
        {
            if (lastOutputDir != null && Directory.Exists(lastOutputDir))
                System.Diagnostics.Process.Start("explorer.exe", lastOutputDir);
        };

        // Files list
        lvFiles = new ListView
        {
            Location = new Point(12, 248),
            Size = new Size(755, 315),
            View = View.Details,
            FullRowSelect = true,
            MultiSelect = false
        };
        lvFiles.Columns.Add("File", 500);
        lvFiles.Columns.Add("Kích thước", 100);
        lvFiles.Columns.Add("Loại", 120);

        // Log
        rtbLog = new RichTextBox
        {
            Location = new Point(12, 248),
            Size = new Size(755, 315),
            ReadOnly = true,
            Font = new Font("Consolas", 9),
            BackColor = Color.White,
            Visible = false,
            WordWrap = false
        };

        var tabControl = new TabControl
        {
            Location = new Point(12, 248),
            Size = new Size(755, 315)
        };

        var tabFiles = new TabPage("Danh sách files");
        tabFiles.Controls.Add(lvFiles);

        var tabLog = new TabPage("Log chi tiết");
        tabLog.Controls.Add(rtbLog);

        tabControl.TabPages.Add(tabFiles);
        tabControl.TabPages.Add(tabLog);

        this.Controls.AddRange(new Control[]
        {
            lblTitle, lblSub, dropPanel, txtPath, btnBrowse,
            cmbType, lblKey, txtKey, btnDecode, progressBar, lblOutputPath,
            lblStatus, tabControl, btnOpenOutput
        });
    }

    private async void BtnDecode_Click(object? sender, EventArgs e)
    {
        var path = txtPath.Text.Trim();
        if (string.IsNullOrEmpty(path))
        {
            MessageBox.Show("Vui lòng chọn file hoặc thư mục!", "Thiếu input", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        if (!File.Exists(path) && !Directory.Exists(path))
        {
            MessageBox.Show($"Không tìm thấy: {path}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        btnDecode.Enabled = false;
        progressBar.Visible = true;
        lblStatus.Text = "Đang xử lý...";
        lblStatus.ForeColor = Color.Gray;
        lvFiles.Items.Clear();
        rtbLog.Clear();
        btnOpenOutput.Visible = false;
        lblOutputPath.Text = "";

        var type = cmbType.SelectedItem?.ToString() ?? "auto";
        var outputDir = GetDefaultOutputPath(path);

        await Task.Run(() =>
        {
            Directory.CreateDirectory(outputDir);

            if (type == "auto")
                type = DetectType(path);

            lastResult = type switch
            {
                "pkg" => new PkgUnpacker().Decode(path, outputDir),
                "plugin" => new PluginPackReader().Decode(path, outputDir),
                "map" => new MiniWorldMapReader().Decode(path, outputDir),
                "lua" => new LuaProcessor().Decode(path, outputDir, GetXXTEAKey()),
                _ => new DecodeResult { Success = false, Errors = { $"Unknown type: {type}" } }
            };

            lastOutputDir = outputDir;
        });

        DisplayResult(lastResult!, type);
        btnDecode.Enabled = true;
        progressBar.Visible = false;
        lblOutputPath.Text = $"Output: {lastOutputDir}";
    }

    private void DisplayResult(DecodeResult result, string type)
    {
        Invoke(() =>
        {
            lvFiles.Items.Clear();
            rtbLog.Clear();

            if (result.Success)
            {
                lblStatus.Text = $"THÀNH CÔNG - {result.FileType} - {result.ExtractedFiles.Count} files extracted";
                lblStatus.ForeColor = Color.Green;
            }
            else
            {
                lblStatus.Text = $"THẤT BẠI - {string.Join(", ", result.Errors)}";
                lblStatus.ForeColor = Color.Red;
            }

            AppendLog($"=== MiniWorld Decoder ===");
            AppendLog($"Input : {result.FilePath}");
            AppendLog($"Type   : {type} → {result.FileType}");
            AppendLog($"Status : {(result.Success ? "Success" : "Failed")}");
            AppendLog($"Output : {lastOutputDir}");
            AppendLog("");

            foreach (var (k, v) in result.Metadata)
            {
                if (k is "MapInfo" or "IssuesBySeverity") continue;
                if (k == "APIList" && v is string s && s.Length > 100)
                {
                    AppendLog($"  {k}: {s[..100]}...");
                    continue;
                }
                AppendLog($"  {k}: {v}");
            }

            if (result.Warnings.Count > 0)
            {
                AppendLog("");
                AppendLog($"--- Warnings ({result.Warnings.Count}) ---");
                foreach (var w in result.Warnings) AppendLog($"  ! {w}");
            }

            if (result.Errors.Count > 0)
            {
                AppendLog("");
                AppendLog($"--- Errors ({result.Errors.Count}) ---");
                foreach (var e in result.Errors) AppendLog($"  x {e}");
            }

            AppendLog("");
            AppendLog($"--- Extracted Files ({result.ExtractedFiles.Count}) ---");
            foreach (var file in result.ExtractedFiles)
            {
                var fi = new FileInfo(file);
                var ext = Path.GetExtension(file).ToLower();
                var size = fi.Exists ? FormatSize(fi.Length) : "?";
                lvFiles.Items.Add(new ListViewItem(new[] { file, size, ext }));
                AppendLog($"  {file} ({size})");
            }

            btnOpenOutput.Visible = true;
        });
    }

    private void AppendLog(string text)
    {
        rtbLog.AppendText(text + "\n");
        rtbLog.ScrollToCaret();
    }

    private static string GetDefaultOutputPath(string input)
    {
        try
        {
            var name = Path.GetFileNameWithoutExtension(input);
            if (string.IsNullOrEmpty(name))
                name = new DirectoryInfo(input).Name;
            var dir = Path.GetDirectoryName(Path.GetFullPath(input)) ?? ".";
            return Path.Combine(dir, name + "_decoded");
        }
        catch { return Path.Combine(Environment.CurrentDirectory, "output"); }
    }

    private string? GetXXTEAKey()
    {
        var text = txtKey.Text.Trim();
        if (text == "" || text == "(nếu có)")
            return null;
        return text;
    }

    private static string DetectType(string path)
    {
        if (File.Exists(path))
        {
            var ext = Path.GetExtension(path).ToLower();
            if (ext is ".lua" or ".luac" or ".wsc") return "lua";
            if (ext == ".pkg") return "pkg";
            if (ext == ".miniworld") return "map";
            if (ext == ".zip") return "plugin";
            return "pkg";
        }
        if (Directory.Exists(path))
        {
            if (PluginPackReader.IsPluginPack(path)) return "plugin";
            if (MiniWorldMapReader.IsMiniWorldMap(path)) return "map";
            return "map";
        }
        return "unknown";
    }

    private static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
        < 1024 * 1024 * 1024 => $"{bytes / (1024.0 * 1024):F1} MB",
        _ => $"{bytes / (1024.0 * 1024 * 1024):F1} GB"
    };
}
