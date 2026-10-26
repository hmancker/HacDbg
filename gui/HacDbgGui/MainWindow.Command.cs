using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using HacDbgGui.Interop;
using Wpf.Ui.Appearance;
using ICSharpCode.AvalonEdit.Document;

namespace HacDbgGui;

public partial class MainWindow
{
    private readonly CommandSearchColorizer _searchColorizer = new();
    private readonly List<CompletionChoice> _completionItems = new();

    private ulong _completionRequestId;
    private string _completionToken = string.Empty;
    private int _completionPollGeneration;
    private bool _applyingCompletion;
    private const int SearchStatusQuietMilliseconds = 200;

    private DispatcherTimer? _searchStatusTimer;
    private int _searchCurrentOffset = -1;
    private int _searchMatchCount;

    private void InitializeCommandChrome()
    {
        CommandOutput.TextArea.TextView.LineTransformers.Add(_searchColorizer);
        CommandOutput.Document.Changed += CommandOutput_DocumentChanged;
        GuiTheme.Changed += OnGuiThemeChanged;
        OnGuiThemeChanged();
    }

    private void ReleaseCommandChrome()
    {
        GuiTheme.Changed -= OnGuiThemeChanged;
        CommandOutput.Document.Changed -= CommandOutput_DocumentChanged;
        StopSearchStatusTimer();
        _completionPollGeneration++;
    }

    private void OnGuiThemeChanged()
    {
        if (IsLoaded)
        {
            ApplicationThemeManager.Apply(this);
        }

        if (TryFindResource("WindowBackgroundBrush") is Brush windowBrush)
        {
            Background = windowBrush;
        }

        if (TryFindResource("SurfaceBrush") is Brush surface)
        {
            CommandOutput.Background = surface;
        }

        if (TryFindResource("ForegroundBrush") is Brush foreground)
        {
            CommandOutput.Foreground = foreground;
        }
        ThemeButton.Content = GuiTheme.IsLight ? "暗色主题" : "亮色主题";
        _searchColorizer.RefreshBrushes();
        CommandOutput.TextArea.TextView.Redraw();
        TraceViewHost.ApplyTheme();
    }

    private void ThemeButton_Click(object sender, RoutedEventArgs e)
    {
        GuiTheme.Apply(GuiTheme.IsLight == false);
        SaveGuiSettings();
    }

    private void SearchButton_Click(object sender, RoutedEventArgs e)
    {
        OpenCommandSearch();
    }

    private void CommandSearchBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            MoveSearch((Keyboard.Modifiers & ModifierKeys.Shift) == 0);
            return;
        }

        if (e.Key == Key.Escape)
        {
            e.Handled = true;
            CloseCommandSearch();
        }
    }

    private void CommandSearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        _searchCurrentOffset = -1;
        RefreshSearch(selectNearest: true);
    }

    private void CommandSearchPrevious_Click(object sender, RoutedEventArgs e)
    {
        MoveSearch(forward: false);
    }

    private void CommandSearchNext_Click(object sender, RoutedEventArgs e)
    {
        MoveSearch(forward: true);
    }

    private void CommandSearchClose_Click(object sender, RoutedEventArgs e)
    {
        CloseCommandSearch();
    }

    private void OpenCommandSearch()
    {
        CloseCompletion();
        CommandSearchBar.Visibility = Visibility.Visible;
        ActivateDocument("command");

        if (CommandOutput.SelectionLength > 0 &&
            CommandOutput.SelectionLength <= 200 &&
            CommandOutput.SelectedText.Contains('\n') == false)
        {
            CommandSearchBox.Text = CommandOutput.SelectedText;
        }

        bool selectNearest = _searchCurrentOffset < 0;
        Dispatcher.BeginInvoke(
            new Action(() =>
            {
                CommandSearchBox.Focus();
                CommandSearchBox.SelectAll();
                RefreshSearch(selectNearest: selectNearest);
            }),
            DispatcherPriority.Input);
    }

    private void CloseCommandSearch()
    {
        CommandSearchBar.Visibility = Visibility.Collapsed;
        StopSearchStatusTimer();
        _searchColorizer.Query = string.Empty;
        _searchColorizer.CurrentOffset = -1;
        _searchCurrentOffset = -1;
        _searchMatchCount = 0;
        CommandSearchStatus.Text = string.Empty;
        CommandOutput.TextArea.TextView.Redraw();
        FocusCommandInput();
    }

    private void MoveSearch(bool forward)
    {
        if (CommandSearchBar.Visibility != Visibility.Visible)
        {
            OpenCommandSearch();
        }

        string query = CommandSearchBox.Text;

        if (string.IsNullOrEmpty(query))
        {
            CommandSearchStatus.Text = "输入文本";
            return;
        }

        string text = CommandOutput.Text;
        int found = forward ? FindForward(text, query) : FindBackward(text, query);
        SelectSearchMatch(found, query.Length);
        UpdateSearchStatus(query);
    }

    private void RefreshSearch(bool selectNearest)
    {
        string query = CommandSearchBox.Text;
        _searchColorizer.Query = query;
        _searchColorizer.CurrentOffset = _searchCurrentOffset;

        if (string.IsNullOrEmpty(query))
        {
            _searchMatchCount = 0;
            _searchCurrentOffset = -1;
            _searchColorizer.CurrentOffset = -1;
            CommandSearchStatus.Text = "输入文本";
            CommandOutput.TextArea.TextView.Redraw();
            return;
        }

        if (selectNearest)
        {
            int found = FindForward(CommandOutput.Text, query);
            SelectSearchMatch(found, query.Length);
        }

        UpdateSearchStatus(query);
        CommandOutput.TextArea.TextView.Redraw();
    }

    private void UpdateSearchStatus(string query)
    {
        _searchMatchCount = CountMatches(CommandOutput.Text, query);

        if (_searchMatchCount == 0)
        {
            CommandSearchStatus.Text = "没有匹配";
            _searchColorizer.CurrentOffset = -1;
            return;
        }

        int index = MatchIndex(CommandOutput.Text, query, _searchCurrentOffset);
        CommandSearchStatus.Text = index > 0 ? $"{index}/{_searchMatchCount}" : $"{_searchMatchCount}";
    }

    private void SelectSearchMatch(int offset, int length)
    {
        if (offset < 0 || length <= 0 || offset + length > CommandOutput.Document.TextLength)
        {
            _searchCurrentOffset = -1;
            _searchColorizer.CurrentOffset = -1;
            return;
        }

        _searchCurrentOffset = offset;
        _searchColorizer.CurrentOffset = offset;
        CommandOutput.Select(offset, length);
        DocumentLine line = CommandOutput.Document.GetLineByOffset(offset);
        CommandOutput.ScrollTo(line.LineNumber, 0);
    }

    private int FindForward(string text, string query)
    {
        int start = _searchCurrentOffset >= 0 ? _searchCurrentOffset + 1 : CommandOutput.SelectionStart;

        if (start < 0)
        {
            start = 0;
        }

        if (start > text.Length)
        {
            start = text.Length;
        }

        int found = text.IndexOf(query, start, StringComparison.OrdinalIgnoreCase);

        if (found < 0 && start > 0)
        {
            found = text.IndexOf(query, 0, StringComparison.OrdinalIgnoreCase);
        }

        return found;
    }

    private int FindBackward(string text, string query)
    {
        int start = _searchCurrentOffset >= 0 ? _searchCurrentOffset - 1 : CommandOutput.SelectionStart - 1;

        if (start >= text.Length)
        {
            start = text.Length - 1;
        }

        int found = start >= 0
            ? text.LastIndexOf(query, start, StringComparison.OrdinalIgnoreCase)
            : -1;

        if (found < 0 && text.Length > 0)
        {
            found = text.LastIndexOf(query, text.Length - 1, StringComparison.OrdinalIgnoreCase);
        }

        return found;
    }

    private void CommandOutput_DocumentChanged(object? sender, DocumentChangeEventArgs e)
    {
        if (CommandSearchBar.Visibility != Visibility.Visible || string.IsNullOrEmpty(CommandSearchBox.Text))
        {
            return;
        }

        int oldLength = CommandOutput.Document.TextLength - e.InsertionLength + e.RemovalLength;
        bool appendOnly = e.RemovalLength == 0 && e.Offset == oldLength;

        if (e.Offset == 0 && e.RemovalLength > 0 && _searchCurrentOffset >= 0)
        {
            if (_searchCurrentOffset < e.RemovalLength)
            {
                _searchCurrentOffset = -1;
            }
            else
            {
                _searchCurrentOffset -= e.RemovalLength;
            }

            _searchColorizer.CurrentOffset = _searchCurrentOffset;
        }
        else if (_searchCurrentOffset >= CommandOutput.Document.TextLength)
        {
            _searchCurrentOffset = -1;
            _searchColorizer.CurrentOffset = -1;
        }

        if (appendOnly)
        {
            ScheduleSearchStatus();
            return;
        }

        UpdateSearchStatus(CommandSearchBox.Text);
        CommandOutput.TextArea.TextView.Redraw();
    }

    private void ScheduleSearchStatus()
    {
        if (_searchStatusTimer is null)
        {
            _searchStatusTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(SearchStatusQuietMilliseconds)
            };
            _searchStatusTimer.Tick += SearchStatusTimer_Tick;
        }

        _searchStatusTimer.Stop();
        _searchStatusTimer.Start();
    }

    private void SearchStatusTimer_Tick(object? sender, EventArgs e)
    {
        _searchStatusTimer?.Stop();

        if (CommandSearchBar.Visibility != Visibility.Visible || string.IsNullOrEmpty(CommandSearchBox.Text))
        {
            return;
        }

        UpdateSearchStatus(CommandSearchBox.Text);
    }

    private void StopSearchStatusTimer()
    {
        if (_searchStatusTimer is null)
        {
            return;
        }

        _searchStatusTimer.Stop();
        _searchStatusTimer.Tick -= SearchStatusTimer_Tick;
        _searchStatusTimer = null;
    }

    private void CommandInput_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_applyingCompletion || CompletionPopup.IsOpen == false)
        {
            return;
        }

        CloseCompletion();
    }

    private void HandleCommandInputKey(KeyEventArgs e)
    {
        Key key = e.Key == Key.System ? e.SystemKey : e.Key;
        bool shift = (Keyboard.Modifiers & ModifierKeys.Shift) != 0;
        bool control = (Keyboard.Modifiers & ModifierKeys.Control) != 0;

        if (key == Key.Tab && control == false)
        {
            e.Handled = true;

            if (CompletionPopup.IsOpen && HasSelectableCompletion())
            {
                MoveCompletion(shift ? -1 : 1);
            }
            else
            {
                RequestCompletion();
            }

            return;
        }

        if (CompletionPopup.IsOpen && (key == Key.Up || key == Key.Down))
        {
            e.Handled = true;
            MoveCompletion(key == Key.Up ? -1 : 1);
            return;
        }

        if (CompletionPopup.IsOpen && key == Key.Enter)
        {
            e.Handled = true;
            AcceptSelectedCompletion();
            return;
        }

        if (CompletionPopup.IsOpen && key == Key.Escape)
        {
            e.Handled = true;
            CloseCompletion();
            return;
        }

        if (key != Key.Up && key != Key.Down)
        {
            return;
        }

        e.Handled = true;

        if (_history.Count == 0)
        {
            return;
        }

        if (key == Key.Up)
        {
            if (_historyIndex > 0)
            {
                _historyIndex--;
            }

            CommandInput.Text = _history[_historyIndex];
        }
        else
        {
            if (_historyIndex < _history.Count)
            {
                _historyIndex++;
            }

            CommandInput.Text = _historyIndex == _history.Count ? string.Empty : _history[_historyIndex];
        }

        CommandInput.CaretIndex = CommandInput.Text.Length;
    }

    private bool HandleSearchShortcut(Key key, bool control, bool shift)
    {
        if (control && key == Key.F)
        {
            OpenCommandSearch();
            return true;
        }

        if (key == Key.F3 && CommandSearchBar.Visibility == Visibility.Visible)
        {
            MoveSearch(shift == false);
            return true;
        }

        if (key == Key.Escape && CommandSearchBox.IsKeyboardFocusWithin)
        {
            CloseCommandSearch();
            return true;
        }

        if (key == Key.Escape && CompletionPopup.IsOpen)
        {
            CloseCompletion();
            return true;
        }

        return false;
    }

    private void PollCompletions()
    {
        try
        {
            PollCompletionsCore();
        }
        catch (Exception error)
        {
            GuiDiagnostics.WriteException("completion poll", error);
            _completionRequestId = 0;
            ShowCompletionMessage("符号补全失败");
        }
    }

    private void PollCompletionsCore()
    {
        if (_core is null || _completionRequestId == 0)
        {
            return;
        }

        ulong requestId = _completionRequestId;

        if (_core.GetCompletionStatus(out HacDbgCoreCompletionStatus status) != 0 ||
            status.Pending != 0 ||
            status.CompletedRequestId != requestId)
        {
            return;
        }

        if (_core.CopyCompletions(requestId, status.Count, out string[] matches) != 0 ||
            _completionRequestId != requestId ||
            CurrentToken() != _completionToken)
        {
            return;
        }

        _completionRequestId = 0;

        if (status.Failed != 0)
        {
            ShowCompletionMessage("符号补全失败");
            return;
        }

        if (matches.Length == 0)
        {
            ShowCompletionMessage("没有匹配的符号");
            return;
        }

        ApplyCommonPrefix(matches);
        ShowCompletionList(matches, (int)status.Total);
    }

    private void RequestCompletion()
    {
        if (CommandInput.IsEnabled == false)
        {
            return;
        }

        try
        {
            RequestCompletionCore();
        }
        catch (Exception error)
        {
            GuiDiagnostics.WriteException("completion", error);
            ShowCompletionMessage("命令补全失败");
        }
    }

    private void RequestCompletionCore()
    {
        string token = CurrentToken();

        if (token.Contains('!'))
        {
            int bang = token.IndexOf('!');

            if (bang + 1 >= token.Length)
            {
                ShowCompletionMessage("没有匹配的符号");
                return;
            }

            RequestSymbolCompletion(token);
            return;
        }

        if (HacDbgCore.CompleteCommands(token, out string[] matches) != 0)
        {
            ShowCompletionMessage("命令补全失败");
            return;
        }

        if (matches.Length == 0)
        {
            ShowCompletionMessage("没有匹配的命令");
            return;
        }

        ApplyCommonPrefix(matches);
        ShowCompletionList(matches, matches.Length);
    }

    private void RequestSymbolCompletion(string token)
    {
        if (_core is null || _started == false)
        {
            ShowCompletionMessage("未连接，不能查找符号");
            return;
        }

        ulong requestId = _core.RequestCompletions(token);

        if (requestId == 0)
        {
            ShowCompletionMessage("符号补全失败");
            return;
        }

        _completionRequestId = requestId;
        _completionToken = token;
        ShowCompletionMessage("正在查找符号...");
        StartCompletionPoll();
    }

    private void StartCompletionPoll()
    {
        int generation = ++_completionPollGeneration;
        _ = PollCompletionLoop(generation);
    }

    private async Task PollCompletionLoop(int generation)
    {
        for (int attempt = 0; attempt < 40; attempt++)
        {
            await Task.Delay(25);

            if (generation != _completionPollGeneration)
            {
                return;
            }

            try
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    if (generation == _completionPollGeneration)
                    {
                        PollCompletions();
                    }
                }, DispatcherPriority.Background);
            }
            catch (Exception)
            {
                return;
            }

            if (_completionRequestId == 0 || generation != _completionPollGeneration)
            {
                return;
            }
        }
    }

    private void ShowCompletionList(IReadOnlyList<string> matches, int total)
    {
        _completionItems.Clear();

        foreach (string match in matches)
        {
            if (string.IsNullOrEmpty(match))
            {
                continue;
            }

            _completionItems.Add(new CompletionChoice { Text = match, CanSelect = true });
        }

        if (total > _completionItems.Count)
        {
            _completionItems.Add(new CompletionChoice
            {
                Text = $"还有 {total - _completionItems.Count} 个匹配",
                CanSelect = false
            });
        }

        CompletionList.ItemsSource = null;
        CompletionList.ItemsSource = _completionItems;
        CompletionList.SelectedIndex = FirstSelectableIndex();
        CompletionPopup.IsOpen = _completionItems.Count > 0;
    }

    private void ShowCompletionMessage(string message)
    {
        _completionItems.Clear();
        _completionItems.Add(new CompletionChoice { Text = message, CanSelect = false });
        CompletionList.ItemsSource = null;
        CompletionList.ItemsSource = _completionItems;
        CompletionList.SelectedIndex = -1;
        CompletionPopup.IsOpen = true;
    }

    private void CloseCompletion()
    {
        CompletionPopup.IsOpen = false;
        _completionRequestId = 0;
        _completionToken = string.Empty;
        _completionPollGeneration++;
    }

    private void AcceptSelectedCompletion()
    {
        if (CompletionList.SelectedItem is CompletionChoice choice && choice.CanSelect)
        {
            AcceptCompletion(choice.Text);
            return;
        }

        CloseCompletion();
    }

    private void CompletionList_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (FindAncestor<ListBoxItem>(e.OriginalSource as DependencyObject) is not ListBoxItem item ||
            item.DataContext is not CompletionChoice choice ||
            choice.CanSelect == false)
        {
            return;
        }

        AcceptCompletion(choice.Text);
        e.Handled = true;
    }

    private void AcceptCompletion(string match)
    {
        (int begin, int length) = TokenRange(CommandInput.Text, CommandInput.CaretIndex);
        string insertion = match.Contains('!') ? match : match + " ";
        ReplaceToken(begin, length, insertion);
        CloseCompletion();
        CommandInput.Focus();
        CommandInput.CaretIndex = Math.Min(begin + insertion.Length, CommandInput.Text.Length);
    }

    private void ApplyCommonPrefix(IReadOnlyList<string> matches)
    {
        string common = CommonPrefix(matches);
        (int begin, int length) = TokenRange(CommandInput.Text, CommandInput.CaretIndex);
        string token = length == 0 ? string.Empty : CommandInput.Text.Substring(begin, length);

        if (common.Length <= token.Length)
        {
            return;
        }

        ReplaceToken(begin, length, common);
        CommandInput.CaretIndex = Math.Min(begin + common.Length, CommandInput.Text.Length);
        _completionToken = common;
    }

    private void ReplaceToken(int begin, int length, string insertion)
    {
        _applyingCompletion = true;

        try
        {
            string line = CommandInput.Text;
            CommandInput.Text = line.Remove(begin, length).Insert(begin, insertion);
        }
        finally
        {
            _applyingCompletion = false;
        }
    }

    private void MoveCompletion(int delta)
    {
        if (HasSelectableCompletion() == false)
        {
            return;
        }

        int index = CompletionList.SelectedIndex;
        int count = _completionItems.Count;

        for (int step = 0; step < count; step++)
        {
            if (index < 0)
            {
                index = delta > 0 ? 0 : count - 1;
            }
            else
            {
                index = (index + delta + count) % count;
            }

            if (_completionItems[index].CanSelect)
            {
                CompletionList.SelectedIndex = index;
                CompletionList.ScrollIntoView(CompletionList.SelectedItem);
                return;
            }
        }
    }

    private bool HasSelectableCompletion()
    {
        return _completionItems.Exists(item => item.CanSelect);
    }

    private int FirstSelectableIndex()
    {
        return _completionItems.FindIndex(item => item.CanSelect);
    }

    private string CurrentToken()
    {
        (int begin, int length) = TokenRange(CommandInput.Text, CommandInput.CaretIndex);
        return length == 0 ? string.Empty : CommandInput.Text.Substring(begin, length);
    }

    private static (int Begin, int Length) TokenRange(string line, int cursor)
    {
        if (cursor < 0)
        {
            cursor = 0;
        }

        if (cursor > line.Length)
        {
            cursor = line.Length;
        }

        int before = cursor == 0 ? -1 : line.LastIndexOf(' ', cursor - 1);
        int begin = before < 0 ? 0 : before + 1;
        int end = line.IndexOf(' ', cursor);

        if (end < 0)
        {
            end = line.Length;
        }

        if (end < begin)
        {
            end = begin;
        }

        return (begin, end - begin);
    }

    private static string CommonPrefix(IReadOnlyList<string> matches)
    {
        if (matches.Count == 0)
        {
            return string.Empty;
        }

        string common = matches[0];

        foreach (string match in matches)
        {
            int length = 0;
            int limit = Math.Min(common.Length, match.Length);

            while (length < limit &&
                   char.ToLowerInvariant(common[length]) == char.ToLowerInvariant(match[length]))
            {
                length++;
            }

            common = common[..length];

            if (common.Length == 0)
            {
                break;
            }
        }

        return common;
    }

    private static int CountMatches(string text, string query)
    {
        if (string.IsNullOrEmpty(query) || string.IsNullOrEmpty(text))
        {
            return 0;
        }

        int count = 0;
        int index = 0;

        while (index < text.Length && count < 10000)
        {
            int found = text.IndexOf(query, index, StringComparison.OrdinalIgnoreCase);

            if (found < 0)
            {
                break;
            }

            count++;
            index = found + Math.Max(query.Length, 1);
        }

        return count;
    }

    private static int MatchIndex(string text, string query, int offset)
    {
        if (offset < 0 || string.IsNullOrEmpty(query))
        {
            return 0;
        }

        int count = 0;
        int index = 0;

        while (index <= offset && index < text.Length)
        {
            int found = text.IndexOf(query, index, StringComparison.OrdinalIgnoreCase);

            if (found < 0 || found > offset)
            {
                break;
            }

            count++;
            index = found + Math.Max(query.Length, 1);
        }

        return count;
    }

    protected override void OnPreviewMouseDown(MouseButtonEventArgs e)
    {
        base.OnPreviewMouseDown(e);

        if (CompletionPopup.IsOpen == false)
        {
            return;
        }

        if (e.OriginalSource is DependencyObject source && IsWithin(CommandInput, source))
        {
            return;
        }

        CloseCompletion();
    }

    private static T? FindAncestor<T>(DependencyObject? node) where T : DependencyObject
    {
        while (node != null)
        {
            if (node is T match)
            {
                return match;
            }

            node = node is Visual or System.Windows.Media.Media3D.Visual3D
                ? VisualTreeHelper.GetParent(node)
                : LogicalTreeHelper.GetParent(node);
        }

        return null;
    }

    private static bool IsWithin(DependencyObject parent, DependencyObject child)
    {
        while (true)
        {
            if (child == parent)
            {
                return true;
            }

            DependencyObject? next = child is Visual or System.Windows.Media.Media3D.Visual3D
                ? VisualTreeHelper.GetParent(child)
                : LogicalTreeHelper.GetParent(child);

            if (next == null)
            {
                return false;
            }

            child = next;
        }
    }
}

internal sealed class CompletionChoice
{
    public string Text { get; init; } = string.Empty;
    public bool CanSelect { get; init; }
}
