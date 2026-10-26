using System.Windows.Media;
using ICSharpCode.AvalonEdit.Document;
using ICSharpCode.AvalonEdit.Rendering;

namespace HacDbgGui;

internal sealed class CommandSearchColorizer : DocumentColorizingTransformer
{
    private Brush _matchBrush = Brushes.Transparent;
    private Brush _currentBrush = Brushes.Transparent;
    private Brush _currentTextBrush = Brushes.Black;

    public CommandSearchColorizer()
    {
        RefreshBrushes();
    }

    public string Query { get; set; } = string.Empty;

    public int CurrentOffset { get; set; } = -1;

    public void RefreshBrushes()
    {
        Color accent = GuiTheme.ReadColor("AccentColor", Color.FromRgb(0x4C, 0xC2, 0xFF));
        Color text = GuiTheme.ReadColor("AccentTextColor", Color.FromRgb(0x08, 0x10, 0x16));
        _matchBrush = Freeze(Color.FromArgb(0x55, accent.R, accent.G, accent.B));
        _currentBrush = Freeze(accent);
        _currentTextBrush = Freeze(text);
    }

    protected override void ColorizeLine(DocumentLine line)
    {
        if (string.IsNullOrEmpty(Query))
        {
            return;
        }

        string text = CurrentContext.Document.GetText(line);
        int index = 0;

        while (index < text.Length)
        {
            int found = text.IndexOf(Query, index, StringComparison.OrdinalIgnoreCase);

            if (found < 0)
            {
                break;
            }

            int offset = line.Offset + found;
            bool current = offset == CurrentOffset;
            int end = offset + Query.Length;
            ChangeLinePart(offset, end, element =>
            {
                element.TextRunProperties.SetBackgroundBrush(current ? _currentBrush : _matchBrush);

                if (current)
                {
                    element.TextRunProperties.SetForegroundBrush(_currentTextBrush);
                }
            });
            index = found + Math.Max(Query.Length, 1);
        }
    }

    private static SolidColorBrush Freeze(Color color)
    {
        SolidColorBrush brush = new(color);
        brush.Freeze();
        return brush;
    }
}
