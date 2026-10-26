using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;
using Wpf.Ui.Appearance;

namespace HacDbgGui;

internal static class GuiTheme
{
    public const string DarkName = "Dark";
    public const string LightName = "Light";

    private static readonly (string Key, Color Dark, Color Light)[] Palette =
    {
        ("WindowBackgroundColor", Color.FromRgb(0x11, 0x14, 0x18), Color.FromRgb(0xF3, 0xF6, 0xF9)),
        ("SurfaceColor", Color.FromRgb(0x18, 0x1D, 0x23), Color.FromRgb(0xFF, 0xFF, 0xFF)),
        ("SurfaceRaisedColor", Color.FromRgb(0x20, 0x26, 0x2E), Color.FromRgb(0xE7, 0xEE, 0xF5)),
        ("BorderColor", Color.FromRgb(0x30, 0x38, 0x42), Color.FromRgb(0xD0, 0xD7, 0xDE)),
        ("ForegroundColor", Color.FromRgb(0xE6, 0xED, 0xF3), Color.FromRgb(0x1F, 0x23, 0x28)),
        ("MutedColor", Color.FromRgb(0x8B, 0x98, 0xA5), Color.FromRgb(0x59, 0x63, 0x6E)),
        ("AccentColor", Color.FromRgb(0x4C, 0xC2, 0xFF), Color.FromRgb(0x09, 0x69, 0xDA)),
        ("AccentPressedColor", Color.FromRgb(0x2E, 0x9F, 0xD9), Color.FromRgb(0x05, 0x50, 0xAE)),
        ("ErrorColor", Color.FromRgb(0xFF, 0x7B, 0x72), Color.FromRgb(0xCF, 0x22, 0x2E)),
        ("WarningColor", Color.FromRgb(0xE3, 0xB3, 0x41), Color.FromRgb(0x9A, 0x67, 0x00)),
        ("AccentTextColor", Color.FromRgb(0x08, 0x10, 0x16), Color.FromRgb(0xFF, 0xFF, 0xFF))
    };

    public static bool IsLight { get; private set; }

    public static string CurrentName => IsLight ? LightName : DarkName;

    public static event Action? Changed;

    public static bool IsLightName(string? name) =>
        string.Equals(name, LightName, StringComparison.OrdinalIgnoreCase);

    public static void Apply(bool light)
    {
        IsLight = light;
        ResourceDictionary resources = Application.Current.Resources;

        foreach ((string key, Color dark, Color lightColor) in Palette)
        {
            Color color = light ? lightColor : dark;
            resources.Remove(key);
            resources.Add(key, color);
            ApplyBrush(resources, key.Replace("Color", "Brush", StringComparison.Ordinal), color);
        }

        ApplicationThemeManager.Apply(light ? ApplicationTheme.Light : ApplicationTheme.Dark);
        Changed?.Invoke();
    }

    public static bool ReadSavedIsLight()
    {
        try
        {
            string path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "HacDbg",
                "gui-settings.json");

            if (File.Exists(path) == false)
            {
                return false;
            }

            using FileStream stream = File.OpenRead(path);
            SavedTheme? saved = JsonSerializer.Deserialize<SavedTheme>(stream);

            if (saved is null || saved.SchemaVersion != 1)
            {
                return false;
            }

            return IsLightName(saved.Theme);
        }
        catch (Exception error)
        {
            GuiDiagnostics.WriteException("theme load", error);
            return false;
        }
    }

    public static Color ReadColor(string key, Color fallback)
    {
        if (Application.Current?.TryFindResource(key) is Color color)
        {
            return color;
        }

        return fallback;
    }

    private static void ApplyBrush(ResourceDictionary resources, string key, Color color)
    {
        if (resources[key] is not SolidColorBrush brush)
        {
            return;
        }

        if (brush.IsFrozen)
        {
            resources[key] = new SolidColorBrush(color);
            return;
        }

        try
        {
            if (brush.Color != color)
            {
                brush.Color = color;
            }
        }
        catch (InvalidOperationException)
        {
        }
    }

    private sealed class SavedTheme
    {
        public int SchemaVersion { get; set; }
        public string? Theme { get; set; }
    }
}
