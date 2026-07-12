using MiniWorldDecoder.Models;
using MiniWorldDecoder.Modules;

namespace MiniWorldDecoderUI;

static class Program
{
    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}
