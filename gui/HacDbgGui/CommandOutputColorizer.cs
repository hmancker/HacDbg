using System.Windows.Media;
using ICSharpCode.AvalonEdit.Document;
using ICSharpCode.AvalonEdit.Rendering;

namespace HacDbgGui;

internal sealed class CommandOutputColorizer : DocumentColorizingTransformer
{
    private readonly Brush _errorBrush;
    private readonly Brush _warningBrush;

    public CommandOutputColorizer(Brush errorBrush, Brush warningBrush)
    {
        _errorBrush = errorBrush;
        _warningBrush = warningBrush;
    }

    protected override void ColorizeLine(DocumentLine line)
    {
        string text = CurrentContext.Document.GetText(line);
        Brush brush;

        if (text.Contains("err,", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("[error]", StringComparison.OrdinalIgnoreCase))
        {
            brush = _errorBrush;
        }
        else if (text.Contains("warn,", StringComparison.OrdinalIgnoreCase) ||
                 text.Contains("[warning]", StringComparison.OrdinalIgnoreCase))
        {
            brush = _warningBrush;
        }
        else
        {
            return;
        }

        ChangeLinePart(line.Offset, line.EndOffset, element =>
        {
            element.TextRunProperties.SetForegroundBrush(brush);
        });
    }
}
