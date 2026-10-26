using System.IO;

namespace HacDbgGui;

internal static class GuiDiagnostics
{
    private const long MaximumLogBytes = 1024 * 1024;
    private static readonly object Sync = new();

    public static string LogPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "HacDbg",
        "HacDbgGui.log");

    public static void Initialize()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!);
        }
        catch (Exception error)
        {
            WriteException("diagnostics initialize", error);
        }
    }

    public static void Write(string category, string message)
    {
        try
        {
            lock (Sync)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!);
                RotateIfNeeded();

                using StreamWriter writer = new(LogPath, append: true);
                writer.Write(DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss.fff zzz"));
                writer.Write(" [");
                writer.Write(category);
                writer.Write("] ");
                writer.WriteLine(message);
            }
        }
        catch
        {
            // Diagnostics must never turn a handled failure into a second failure.
        }
    }

    public static void WriteException(string category, Exception error)
    {
        Write(category, error.ToString());
    }

    private static void RotateIfNeeded()
    {
        FileInfo log = new(LogPath);

        if (log.Exists == false || log.Length < MaximumLogBytes)
        {
            return;
        }

        File.Move(LogPath, LogPath + ".1", overwrite: true);
    }
}
