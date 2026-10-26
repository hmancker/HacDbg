using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using HacDbgGui.Interop;

namespace HacDbgGui;

public partial class MainWindow
{
    private const int MemoryCachePageLimit = 32;

    private readonly ObservableCollection<ModuleRow> _modules = new();
    private readonly ObservableCollection<ProcessRow> _processes = new();
    private readonly ObservableCollection<ThreadRow> _threads = new();
    private readonly ObservableCollection<StackRow> _stack = new();
    private readonly ObservableCollection<MemoryRow> _memoryRows = new();
    private readonly ObservableCollection<DisassemblyRow> _disassembly = new();
    private readonly Dictionary<(ulong Cr3, ulong Address), MemoryPage> _memoryCache = new();
    private readonly Queue<(ulong Cr3, ulong Address)> _memoryCacheOrder = new();
    private readonly List<(ulong Address, ulong Cr3)> _disassemblyHistory = new();
    private ICollectionView? _processView;
    private ICollectionView? _threadView;

    private ulong _modulesRequestId;
    private ulong _processesRequestId;
    private ulong _threadsRequestId;
    private ulong _stackRequestId;
    private ulong _memoryRequestId;
    private ulong _disassemblyRequestId;
    private ulong _resolveRequestId;
    private ulong _threadsEprocess;
    private ulong _threadsUserCr3;
    private ulong _resolveCr3;
    private ulong _pausedCr3;
    private ulong _lastPausedRip;
    private ulong _disassemblyRequestCr3;
    private ulong _disassemblyLastEnd;
    private MemoryPage? _currentMemoryPage;
    private ResolveTarget _resolveTarget;
    private int _disassemblyHistoryIndex = -1;
    private bool _disassemblyRecordPending;
    private bool _pausedNow;
    private bool _viewPollFaulted;
    private bool _symbolLoadWasActive;
    private string _processFilter = string.Empty;
    private string _threadFilter = string.Empty;

    private enum ResolveTarget
    {
        None,
        Memory,
        Disassembly
    }

    private void InitializeStructuredViews()
    {
        ModuleGrid.ItemsSource = _modules;
        _processView = CollectionViewSource.GetDefaultView(_processes);
        _processView.Filter = FilterProcess;
        ProcessGrid.ItemsSource = _processView;
        _threadView = CollectionViewSource.GetDefaultView(_threads);
        _threadView.Filter = FilterThread;
        ThreadGrid.ItemsSource = _threadView;
        StackGrid.ItemsSource = _stack;
        MemoryGrid.ItemsSource = _memoryRows;
        DisassemblyGrid.ItemsSource = _disassembly;
    }

    private void PollStructuredViews()
    {
        if (_core is null || _started == false)
        {
            return;
        }

        try
        {
            UpdateSymbolProgress();
            PollModules();
            PollProcesses();
            PollThreads();
            PollStack();
            PollMemory();
            PollDisassembly();
            PollResolve();
            _viewPollFaulted = false;
        }
        catch (Exception error)
        {
            if (_viewPollFaulted == false)
            {
                _viewPollFaulted = true;
                AppendError($"structured view update failed: {error.Message}");
            }
        }
    }

    private void UpdateSymbolProgress()
    {
        HacDbgCore? core = _core;

        if (core is null || _started == false || core.GetSymbolProgress(out HacDbgCoreSymbolProgress progress) != 0)
        {
            return;
        }

        bool active = progress.Active != 0;

        if (active == false)
        {
            if (_symbolLoadWasActive)
            {
                _symbolLoadWasActive = false;
                RequestModules();
                SymbolProgressPanel.Visibility = Visibility.Collapsed;
            }

            if (LoadSymbolsButton.IsEnabled != _started)
            {
                LoadSymbolsButton.IsEnabled = _started;
            }

            return;
        }

        _symbolLoadWasActive = true;
        SymbolProgressPanel.Visibility = Visibility.Visible;
        LoadSymbolsButton.IsEnabled = false;

        SymbolProgressBar.Maximum = Math.Max(progress.Total, 1u);
        SymbolProgressBar.IsIndeterminate = progress.Total <= 1;
        SymbolProgressBar.Value = Math.Min(progress.Completed, progress.Total);
        SymbolProgressText.Text = $"符号 {progress.Completed}/{progress.Total}";
    }

    private bool TryGetCompletedView(uint view, ulong requestId, out HacDbgCoreViewStatus status)
    {
        status = default;
        HacDbgCore? core = _core;

        return core is not null &&
               requestId != 0 &&
               core.GetViewStatus(view, out status) == 0 &&
               status.CompletedRequestId >= requestId &&
               status.Pending == 0;
    }

    private static bool ViewFailed(HacDbgCoreViewStatus status, TextBlock statusText)
    {
        if (status.Failed == 0)
        {
            return false;
        }

        string message = DecodeUtf8(status.Message);
        statusText.Text = message.Length == 0 ? "读取失败" : message;

        return true;
    }

    private void RequestModules()
    {
        HacDbgCore? core = _core;

        if (core is null || _started == false)
        {
            return;
        }

        _modulesRequestId = core.RequestModules();
        ModulesStatusText.Text = _modulesRequestId == 0 ? "无法排队" : "读取中...";
    }

    private void PollModules()
    {
        HacDbgCore? core = _core;

        if (core is null || TryGetCompletedView(HacDbgCore.ViewModules, _modulesRequestId, out HacDbgCoreViewStatus status) == false)
        {
            return;
        }

        _modulesRequestId = 0;

        if (ViewFailed(status, ModulesStatusText))
        {
            return;
        }

        HacDbgCoreModule[] buffer = new HacDbgCoreModule[HacDbgCore.MaxModules];

        if (core.CopyModules(buffer, (uint)buffer.Length, out uint count) != 0)
        {
            ModulesStatusText.Text = "复制模块失败";
            return;
        }

        _modules.Clear();

        for (uint index = 0; index < count; index++)
        {
            HacDbgCoreModule module = buffer[index];

            _modules.Add(new ModuleRow(
                DecodeUtf8(module.Name),
                $"0x{module.Base:X16}",
                $"0x{module.Size:X}",
                module.Kernel != 0 ? "kernel" : "user",
                module.SymbolsLoaded != 0 ? "pdb" : "—",
                DecodeUtf8(module.SymbolPath),
                module.Base));
        }

        ModulesStatusText.Text = status.Truncated != 0
            ? $"{count} 个，已截断"
            : $"{count} 个";
    }

    private void RequestProcesses()
    {
        HacDbgCore? core = _core;

        if (core is null || _started == false)
        {
            return;
        }

        _processesRequestId = core.RequestProcesses();
        ProcessesStatusText.Text = _processesRequestId == 0 ? "无法排队" : "读取中...";
    }

    private void PollProcesses()
    {
        HacDbgCore? core = _core;

        if (core is null ||
            TryGetCompletedView(HacDbgCore.ViewProcesses, _processesRequestId, out HacDbgCoreViewStatus status) == false)
        {
            return;
        }

        _processesRequestId = 0;

        if (ViewFailed(status, ProcessesStatusText))
        {
            return;
        }

        HacDbgCoreProcess[] buffer = new HacDbgCoreProcess[HacDbgCore.MaxProcesses];

        if (core.CopyProcesses(buffer, (uint)buffer.Length, out uint count) != 0)
        {
            ProcessesStatusText.Text = "复制进程失败";
            return;
        }

        ulong selected = (ProcessGrid.SelectedItem as ProcessRow)?.EprocessValue ?? 0;
        _processes.Clear();

        for (uint index = 0; index < count; index++)
        {
            HacDbgCoreProcess process = buffer[index];

            _processes.Add(new ProcessRow(
                process.Pid.ToString(CultureInfo.InvariantCulture),
                DecodeUtf8(process.Image),
                process.ParentPid.ToString(CultureInfo.InvariantCulture),
                $"0x{process.Eprocess:X16}",
                $"0x{process.UserCr3:X16}",
                process.Eprocess,
                process.UserCr3,
                process.Pid));
        }

        _processView?.Refresh();
        ProcessesStatusText.Text = status.Truncated != 0
            ? $"{count} 个，已截断"
            : $"{count} 个";

        ProcessRow? selection = _processes.FirstOrDefault(process => process.EprocessValue == selected);
        if (selection is null || _processView is null || _processView.Contains(selection) == false)
        {
            selection = _processView?.Cast<ProcessRow>().FirstOrDefault();
        }

        if (selection is not null)
        {
            ProcessGrid.SelectedItem = selection;
            ProcessGrid.ScrollIntoView(selection);
        }
        else
        {
            _threads.Clear();
            ThreadsStatusText.Text = "未选择进程";
        }
    }

    private void RequestThreads(ulong eprocess, ulong userCr3)
    {
        HacDbgCore? core = _core;

        if (core is null || _started == false || eprocess == 0)
        {
            _threads.Clear();
            ThreadsStatusText.Text = "未选择进程";
            return;
        }

        _threadsEprocess = eprocess;
        _threadsUserCr3 = userCr3;
        _threadsRequestId = core.RequestThreads(eprocess);
        ThreadsStatusText.Text = _threadsRequestId == 0 ? "无法排队" : "读取中...";
    }

    private void PollThreads()
    {
        HacDbgCore? core = _core;

        if (core is null || TryGetCompletedView(HacDbgCore.ViewThreads, _threadsRequestId, out HacDbgCoreViewStatus status) == false)
        {
            return;
        }

        _threadsRequestId = 0;

        if (ViewFailed(status, ThreadsStatusText))
        {
            _threads.Clear();
            return;
        }

        HacDbgCoreThread[] buffer = new HacDbgCoreThread[HacDbgCore.MaxThreads];

        if (core.CopyThreads(buffer, (uint)buffer.Length, out uint count) != 0)
        {
            ThreadsStatusText.Text = "复制线程失败";
            return;
        }

        _threads.Clear();

        for (uint index = 0; index < count; index++)
        {
            HacDbgCoreThread thread = buffer[index];
            ulong jumpAddress = thread.InstructionPointer != 0 ? thread.InstructionPointer : thread.Win32Start;

            _threads.Add(new ThreadRow(
                thread.Tid.ToString(CultureInfo.InvariantCulture),
                DecodeUtf8(thread.StateName),
                thread.InstructionPointer != 0 ? $"0x{thread.InstructionPointer:X16}" : "—",
                thread.KernelMode != 0 ? "kernel" : "user",
                ((int)thread.Priority).ToString(CultureInfo.InvariantCulture),
                jumpAddress,
                thread.Cr3 != 0 ? thread.Cr3 : _threadsUserCr3,
                thread.Tid,
                thread.Pid,
                DecodeUtf8(thread.Image)));
        }

        _threadView?.Refresh();
        ThreadsStatusText.Text = status.Truncated != 0
            ? $"{count} 个，已截断"
            : $"{count} 个";
    }

    private void RequestStack()
    {
        HacDbgCore? core = _core;

        if (core is null || _started == false)
        {
            return;
        }

        if (_pausedNow == false)
        {
            _stack.Clear();
            StackStatusText.Text = "没有暂停线程";
            return;
        }

        _stackRequestId = core.RequestStack(32);
        StackStatusText.Text = _stackRequestId == 0 ? "无法排队" : "读取中...";
    }

    private void PollStack()
    {
        HacDbgCore? core = _core;

        if (core is null || TryGetCompletedView(HacDbgCore.ViewStack, _stackRequestId, out HacDbgCoreViewStatus status) == false)
        {
            return;
        }

        _stackRequestId = 0;

        if (ViewFailed(status, StackStatusText))
        {
            _stack.Clear();
            return;
        }

        HacDbgCoreStackFrame[] buffer = new HacDbgCoreStackFrame[HacDbgCore.MaxStackFrames];

        if (core.CopyStack(buffer, (uint)buffer.Length, out uint count) != 0)
        {
            StackStatusText.Text = "复制调用栈失败";
            return;
        }

        _stack.Clear();

        for (uint index = 0; index < count; index++)
        {
            HacDbgCoreStackFrame frame = buffer[index];

            _stack.Add(new StackRow(
                index.ToString("D2", CultureInfo.InvariantCulture),
                $"0x{frame.ChildSp:X16}",
                frame.HasReturn != 0 ? $"0x{frame.ReturnAddress:X16}" : "????????????????",
                DecodeUtf8(frame.Symbol),
                frame.InstructionPointer));
        }

        StackStatusText.Text = status.Truncated != 0
            ? $"{count} 帧，已截断"
            : $"{count} 帧";
    }

    private void RequestMemoryFromInput()
    {
        HacDbgCore? core = _core;

        if (core is null || _started == false)
        {
            return;
        }

        if (TryReadCr3(MemoryCr3Box, out ulong cr3) == false)
        {
            MemoryStatusText.Text = "CR3 格式无效";
            return;
        }

        string text = MemoryAddressBox.Text.Trim();

        if (text.Length == 0)
        {
            MemoryStatusText.Text = "请输入地址或符号";
            return;
        }

        _resolveTarget = ResolveTarget.Memory;
        _resolveCr3 = cr3;
        _resolveRequestId = core.RequestResolve(text);
        MemoryStatusText.Text = _resolveRequestId == 0 ? "无法排队" : "解析中...";
    }

    private void RequestMemoryPage(ulong address, ulong cr3)
    {
        HacDbgCore? core = _core;

        if (core is null || _started == false)
        {
            return;
        }

        ulong page = address & ~0xFFFUL;
        _memoryRequestId = core.RequestMemory(page, cr3, HacDbgCore.MaxMemoryBytes);
        MemoryStatusText.Text = _memoryRequestId == 0 ? "无法排队" : "读取中...";
    }

    private void PollMemory()
    {
        HacDbgCore? core = _core;

        if (core is null || TryGetCompletedView(HacDbgCore.ViewMemory, _memoryRequestId, out HacDbgCoreViewStatus status) == false)
        {
            return;
        }

        _memoryRequestId = 0;

        if (ViewFailed(status, MemoryStatusText))
        {
            return;
        }

        if (core.CopyMemory(out HacDbgCoreMemory memory) != 0)
        {
            MemoryStatusText.Text = "复制内存失败";
            return;
        }

        int length = (int)Math.Min(memory.BytesValid, (uint)memory.Data.Length);
        byte[] bytes = new byte[length];
        Array.Copy(memory.Data, bytes, length);

        MemoryPage page = new(memory.Address, memory.Cr3, bytes);
        CacheMemoryPage(page);
        ShowMemoryPage(page);
        MemoryStatusText.Text = $"{memory.BytesValid}/{memory.Requested} 字节 · CR3 0x{memory.Cr3:X16}";
    }

    private void CacheMemoryPage(MemoryPage page)
    {
        (ulong Cr3, ulong Address) key = (page.Cr3, page.Address);

        if (_memoryCache.ContainsKey(key) == false)
        {
            _memoryCacheOrder.Enqueue(key);
        }

        _memoryCache[key] = page;

        while (_memoryCache.Count > MemoryCachePageLimit && _memoryCacheOrder.Count != 0)
        {
            _memoryCache.Remove(_memoryCacheOrder.Dequeue());
        }
    }

    private bool TryShowCachedMemory(ulong address, ulong cr3)
    {
        if (_memoryCache.TryGetValue((cr3, address), out MemoryPage? page) == false)
        {
            return false;
        }

        ShowMemoryPage(page);

        return true;
    }

    private void ShowMemoryPage(MemoryPage page)
    {
        _currentMemoryPage = page;
        MemoryAddressBox.Text = $"0x{page.Address:X16}";
        _memoryRows.Clear();

        for (int offset = 0; offset < page.Bytes.Length; offset += 16)
        {
            int count = Math.Min(16, page.Bytes.Length - offset);
            StringBuilder hex = new();
            StringBuilder ascii = new();

            for (int index = 0; index < count; index++)
            {
                byte value = page.Bytes[offset + index];

                if (index != 0)
                {
                    hex.Append(' ');
                }

                hex.Append(value.ToString("X2", CultureInfo.InvariantCulture));
                ascii.Append(value is >= 0x20 and < 0x7F ? (char)value : '.');
            }

            _memoryRows.Add(new MemoryRow(
                $"0x{page.Address + (ulong)offset:X16}",
                hex.ToString(),
                ascii.ToString()));
        }
    }

    private void MoveMemoryPage(int direction)
    {
        if (_currentMemoryPage is null)
        {
            MemoryStatusText.Text = "请先读取一页内存";
            return;
        }

        ulong address = _currentMemoryPage.Address;
        ulong cr3 = _currentMemoryPage.Cr3;

        if (direction < 0)
        {
            if (address < 0x1000)
            {
                MemoryStatusText.Text = "已经到地址下限";
                return;
            }

            address -= 0x1000;
        }
        else
        {
            if (address > ulong.MaxValue - 0x1000)
            {
                MemoryStatusText.Text = "已经到地址上限";
                return;
            }

            address += 0x1000;
        }

        if (TryShowCachedMemory(address, cr3) == false)
        {
            RequestMemoryPage(address, cr3);
        }
        else
        {
            MemoryStatusText.Text = $"缓存页 · CR3 0x{cr3:X16}";
        }
    }

    private void RequestDisassemblyFromInput()
    {
        HacDbgCore? core = _core;

        if (core is null || _started == false)
        {
            return;
        }

        if (TryReadCr3(DisassemblyCr3Box, out ulong cr3) == false)
        {
            DisassemblyStatusText.Text = "CR3 格式无效";
            return;
        }

        string text = DisassemblyAddressBox.Text.Trim();

        if (text.Length == 0)
        {
            DisassemblyStatusText.Text = "请输入地址或符号";
            return;
        }

        _resolveTarget = ResolveTarget.Disassembly;
        _resolveCr3 = cr3;
        _resolveRequestId = core.RequestResolve(text);
        DisassemblyStatusText.Text = _resolveRequestId == 0 ? "无法排队" : "解析中...";
    }

    private void RequestDisassemblyPage(ulong address, ulong cr3, bool recordHistory)
    {
        HacDbgCore? core = _core;

        if (core is null || _started == false)
        {
            return;
        }

        uint count = SelectedInstructionCount();
        _disassemblyRequestCr3 = cr3;
        _disassemblyRecordPending = recordHistory;
        _disassemblyRequestId = core.RequestDisassembly(address, cr3, count);
        DisassemblyStatusText.Text = _disassemblyRequestId == 0 ? "无法排队" : "读取中...";
    }

    private void PollDisassembly()
    {
        HacDbgCore? core = _core;

        if (core is null ||
            TryGetCompletedView(HacDbgCore.ViewDisassembly, _disassemblyRequestId, out HacDbgCoreViewStatus status) == false)
        {
            return;
        }

        _disassemblyRequestId = 0;
        bool recordHistory = _disassemblyRecordPending;
        _disassemblyRecordPending = false;

        if (ViewFailed(status, DisassemblyStatusText))
        {
            _disassembly.Clear();
            return;
        }

        HacDbgCoreInstruction[] buffer = new HacDbgCoreInstruction[HacDbgCore.MaxDisassemblyLines];

        if (core.CopyDisassembly(buffer, (uint)buffer.Length, out uint count) != 0)
        {
            DisassemblyStatusText.Text = "复制反汇编失败";
            return;
        }

        _disassembly.Clear();
        ulong firstAddress = 0;
        ulong lastEnd = 0;

        for (uint index = 0; index < count; index++)
        {
            HacDbgCoreInstruction instruction = buffer[index];

            if (index == 0)
            {
                firstAddress = instruction.Address;
            }

            lastEnd = instruction.Address + instruction.Length;
            _disassembly.Add(new DisassemblyRow(
                $"0x{instruction.Address:X16}",
                DecodeUtf8(instruction.Bytes),
                DecodeUtf8(instruction.Text),
                DecodeUtf8(instruction.Symbol),
                instruction.Address));
        }

        if (count == 0)
        {
            DisassemblyStatusText.Text = "没有可显示的指令";
            return;
        }

        _disassemblyLastEnd = lastEnd;
        DisassemblyAddressBox.Text = $"0x{firstAddress:X16}";

        if (recordHistory == true)
        {
            if (_disassemblyHistoryIndex + 1 < _disassemblyHistory.Count)
            {
                _disassemblyHistory.RemoveRange(
                    _disassemblyHistoryIndex + 1,
                    _disassemblyHistory.Count - _disassemblyHistoryIndex - 1);
            }

            _disassemblyHistory.Add((firstAddress, _disassemblyRequestCr3));
            _disassemblyHistoryIndex = _disassemblyHistory.Count - 1;
        }

        DisassemblyStatusText.Text = status.Truncated != 0
            ? $"{count} 条，已截断"
            : $"{count} 条";
        SelectPausedInstruction();
    }

    private void SelectPausedInstruction()
    {
        if (_pausedNow == false || _lastPausedRip == 0)
        {
            return;
        }

        for (int index = 0; index < _disassembly.Count; index++)
        {
            if (_disassembly[index].AddressValue != _lastPausedRip)
            {
                continue;
            }

            DisassemblyGrid.SelectedIndex = index;
            DisassemblyGrid.ScrollIntoView(_disassembly[index]);
            return;
        }
    }

    private void PollResolve()
    {
        HacDbgCore? core = _core;

        if (core is null || TryGetCompletedView(HacDbgCore.ViewResolve, _resolveRequestId, out HacDbgCoreViewStatus status) == false)
        {
            return;
        }

        _resolveRequestId = 0;

        if (status.Failed != 0)
        {
            string message = DecodeUtf8(status.Message);
            message = message.Length == 0 ? "地址解析失败" : message;

            if (_resolveTarget == ResolveTarget.Memory)
            {
                MemoryStatusText.Text = message;
            }
            else if (_resolveTarget == ResolveTarget.Disassembly)
            {
                DisassemblyStatusText.Text = message;
            }

            return;
        }

        if (core.CopyResolvedAddress(out HacDbgCoreResolvedAddress resolved) != 0)
        {
            if (_resolveTarget == ResolveTarget.Memory)
            {
                MemoryStatusText.Text = "复制解析结果失败";
            }
            else if (_resolveTarget == ResolveTarget.Disassembly)
            {
                DisassemblyStatusText.Text = "复制解析结果失败";
            }

            return;
        }

        string symbol = DecodeUtf8(resolved.Symbol);

        if (_resolveTarget == ResolveTarget.Memory)
        {
            MemoryAddressBox.Text = $"0x{resolved.Address:X16}";
            RequestMemoryPage(resolved.Address, _resolveCr3);
        }
        else if (_resolveTarget == ResolveTarget.Disassembly)
        {
            DisassemblyAddressBox.Text = $"0x{resolved.Address:X16}";
            RequestDisassemblyPage(resolved.Address, _resolveCr3, true);

            if (symbol.Length != 0)
            {
                DisassemblyStatusText.Text = symbol;
            }
        }
    }

    private uint SelectedInstructionCount()
    {
        if (DisassemblyCountBox.SelectedItem is ComboBoxItem item &&
            item.Tag is string text &&
            uint.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint count))
        {
            return count;
        }

        return 64;
    }

    private static bool TryReadCr3(TextBox box, out ulong cr3)
    {
        cr3 = 0;
        string text = box.Text.Trim();

        if (text.Length == 0)
        {
            return true;
        }

        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            text = text[2..];
        }

        return ulong.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out cr3);
    }

    private static string DecodeUtf8(byte[]? bytes)
    {
        if (bytes is null || bytes.Length == 0)
        {
            return string.Empty;
        }

        int length = Array.IndexOf(bytes, (byte)0);

        if (length < 0)
        {
            length = bytes.Length;
        }

        return Encoding.UTF8.GetString(bytes, 0, length);
    }

    private void OpenDisassemblyAt(ulong address, ulong cr3)
    {
        if (address == 0)
        {
            return;
        }

        ActivateDocument("disassembly");
        DisassemblyAddressBox.Text = $"0x{address:X16}";
        DisassemblyCr3Box.Text = cr3 == 0 ? string.Empty : $"0x{cr3:X16}";
        RequestDisassemblyPage(address, cr3, true);
    }

    private void OpenMemoryAt(ulong address, ulong cr3)
    {
        if (address == 0)
        {
            return;
        }

        ActivateDocument("memory");
        MemoryAddressBox.Text = $"0x{address:X16}";
        MemoryCr3Box.Text = cr3 == 0 ? string.Empty : $"0x{cr3:X16}";
        RequestMemoryPage(address, cr3);
    }

    private void UpdateStructuredState(HacDbgCoreState state, bool paused)
    {
        bool canRefresh = _started && state.Running != 0;

        if (RefreshViewsButton.IsEnabled != canRefresh)
        {
            RefreshViewsButton.IsEnabled = canRefresh;
        }

        if (paused == false)
        {
            if (_pausedNow == true)
            {
                _stack.Clear();
                StackStatusText.Text = "没有暂停线程";
            }

            _pausedNow = false;
            _pausedCr3 = 0;
            _lastPausedRip = 0;
            return;
        }

        bool enteredPause = _pausedNow == false;
        _pausedCr3 = state.Registers.Cr3;
        ulong rip = state.Registers.Rip;
        bool pauseChanged = enteredPause || _lastPausedRip != rip;
        _pausedNow = true;
        _lastPausedRip = rip;

        if (pauseChanged == false)
        {
            return;
        }

        RequestStack();

        //
        // A breakpoint hit opens the disassembly view on its own. Follow RIP
        // only keeps later steps on that view.
        //
        if (rip != 0 && (enteredPause || FollowRipCheck.IsChecked == true))
        {
            OpenDisassemblyAt(rip, _pausedCr3);
        }
    }

    private void LoadSymbolsButton_Click(object sender, RoutedEventArgs e)
    {
        ExecuteCommand(".reload /f");
    }

    private void RefreshViewsButton_Click(object sender, RoutedEventArgs e)
    {
        RequestModules();
        RequestProcesses();

        if (ProcessGrid.SelectedItem is ProcessRow process)
        {
            RequestThreads(process.EprocessValue, process.UserCr3Value);
        }

        if (_pausedNow == true)
        {
            RequestStack();
        }
    }

    private void RefreshModulesButton_Click(object sender, RoutedEventArgs e)
    {
        RequestModules();
    }

    private void RefreshProcessesButton_Click(object sender, RoutedEventArgs e)
    {
        RequestProcesses();
    }

    private void RefreshStackButton_Click(object sender, RoutedEventArgs e)
    {
        RequestStack();
    }

    private void ProcessGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ProcessGrid.SelectedItem is ProcessRow process)
        {
            if (_threadsEprocess != process.EprocessValue || _threadsRequestId == 0)
            {
                RequestThreads(process.EprocessValue, process.UserCr3Value);
            }
        }
        else
        {
            _threads.Clear();
            ThreadsStatusText.Text = "未选择进程";
            _threadsEprocess = 0;
        }
    }

    private void ProcessFilterBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        _processFilter = ProcessFilterBox.Text.Trim();
        _processView?.Refresh();
    }

    private void ThreadFilterBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        _threadFilter = ThreadFilterBox.Text.Trim();
        _threadView?.Refresh();
    }

    private bool FilterProcess(object item)
    {
        return item is ProcessRow process &&
               MatchesIdOrName(_processFilter, process.PidValue, process.Image);
    }

    private bool FilterThread(object item)
    {
        return item is ThreadRow thread &&
               MatchesIdsOrName(_threadFilter, thread.TidValue, thread.PidValue, thread.Image);
    }

    private static bool MatchesIdOrName(string filter, ulong id, string name)
    {
        if (filter.Length == 0)
        {
            return true;
        }

        if (TryParseFilterId(filter, out ulong parsedId))
        {
            return id == parsedId;
        }

        return name.Contains(filter, StringComparison.OrdinalIgnoreCase);
    }

    private static bool MatchesIdsOrName(string filter, ulong firstId, ulong secondId, string name)
    {
        if (filter.Length == 0)
        {
            return true;
        }

        if (TryParseFilterId(filter, out ulong parsedId))
        {
            return firstId == parsedId || secondId == parsedId;
        }

        return name.Contains(filter, StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryParseFilterId(string filter, out ulong id)
    {
        id = 0;
        NumberStyles style = NumberStyles.Integer;
        string numeric = filter;

        if (numeric.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            numeric = numeric[2..];
            style = NumberStyles.HexNumber;
        }

        return numeric.Length != 0 &&
               ulong.TryParse(numeric, style, CultureInfo.InvariantCulture, out id);
    }

    private void ModuleGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (ModuleGrid.SelectedItem is ModuleRow module)
        {
            OpenDisassemblyAt(module.BaseAddress, 0);
            e.Handled = true;
        }
    }

    private void ThreadGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (ThreadGrid.SelectedItem is ThreadRow thread && thread.JumpAddress != 0)
        {
            OpenDisassemblyAt(thread.JumpAddress, thread.Cr3);
            e.Handled = true;
        }
    }

    private void StackGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (StackGrid.SelectedItem is StackRow frame && frame.InstructionAddress != 0)
        {
            OpenDisassemblyAt(frame.InstructionAddress, _pausedCr3);
            e.Handled = true;
        }
    }

    private void MemoryReadButton_Click(object sender, RoutedEventArgs e)
    {
        RequestMemoryFromInput();
    }

    private void MemoryRefreshButton_Click(object sender, RoutedEventArgs e)
    {
        if (_currentMemoryPage is not null)
        {
            RequestMemoryPage(_currentMemoryPage.Address, _currentMemoryPage.Cr3);
        }
        else
        {
            RequestMemoryFromInput();
        }
    }

    private void MemoryPreviousButton_Click(object sender, RoutedEventArgs e)
    {
        MoveMemoryPage(-1);
    }

    private void MemoryNextButton_Click(object sender, RoutedEventArgs e)
    {
        MoveMemoryPage(1);
    }

    private void DisassemblyReadButton_Click(object sender, RoutedEventArgs e)
    {
        RequestDisassemblyFromInput();
    }

    private void RipButton_Click(object sender, RoutedEventArgs e)
    {
        if (_pausedNow == false || _lastPausedRip == 0)
        {
            DisassemblyStatusText.Text = "没有暂停线程";
            return;
        }

        OpenDisassemblyAt(_lastPausedRip, _pausedCr3);
    }

    private void DisassemblyPreviousButton_Click(object sender, RoutedEventArgs e)
    {
        if (_disassemblyHistoryIndex <= 0)
        {
            DisassemblyStatusText.Text = "没有上一页";
            return;
        }

        _disassemblyHistoryIndex--;
        (ulong address, ulong cr3) = _disassemblyHistory[_disassemblyHistoryIndex];
        RequestDisassemblyPage(address, cr3, false);
    }

    private void DisassemblyNextButton_Click(object sender, RoutedEventArgs e)
    {
        if (_disassemblyHistoryIndex + 1 < _disassemblyHistory.Count)
        {
            _disassemblyHistoryIndex++;
            (ulong address, ulong cr3) = _disassemblyHistory[_disassemblyHistoryIndex];
            RequestDisassemblyPage(address, cr3, false);
            return;
        }

        if (_disassemblyLastEnd != 0)
        {
            RequestDisassemblyPage(_disassemblyLastEnd, _disassemblyRequestCr3, true);
            return;
        }

        DisassemblyStatusText.Text = "没有下一页";
    }

    private void DisassemblyGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (DisassemblyGrid.SelectedItem is DisassemblyRow instruction)
        {
            OpenMemoryAt(instruction.AddressValue, _disassemblyRequestCr3);
            e.Handled = true;
        }
    }

}

internal sealed class ModuleRow
{
    public ModuleRow(string name, string @base, string size, string kind, string symbols, string symbolPath,
                     ulong baseAddress)
    {
        Name = name;
        Base = @base;
        Size = size;
        Kind = kind;
        Symbols = symbols;
        SymbolPath = symbolPath;
        BaseAddress = baseAddress;
    }

    public string Name { get; }
    public string Base { get; }
    public string Size { get; }
    public string Kind { get; }
    public string Symbols { get; }
    public string SymbolPath { get; }
    public ulong BaseAddress { get; }
}

internal sealed class ProcessRow
{
    public ProcessRow(string pid, string image, string parentPid, string eprocess, string userCr3,
                      ulong eprocessValue, ulong userCr3Value, ulong pidValue)
    {
        Pid = pid;
        Image = image;
        ParentPid = parentPid;
        Eprocess = eprocess;
        UserCr3 = userCr3;
        EprocessValue = eprocessValue;
        UserCr3Value = userCr3Value;
        PidValue = pidValue;
    }

    public string Pid { get; }
    public string Image { get; }
    public string ParentPid { get; }
    public string Eprocess { get; }
    public string UserCr3 { get; }
    public ulong EprocessValue { get; }
    public ulong UserCr3Value { get; }
    public ulong PidValue { get; }
}

internal sealed class ThreadRow
{
    public ThreadRow(string tid, string state, string instructionPointer, string mode, string priority,
                     ulong jumpAddress, ulong cr3, ulong tidValue, ulong pidValue, string image)
    {
        Tid = tid;
        State = state;
        InstructionPointer = instructionPointer;
        Mode = mode;
        Priority = priority;
        JumpAddress = jumpAddress;
        Cr3 = cr3;
        TidValue = tidValue;
        PidValue = pidValue;
        Image = image;
    }

    public string Tid { get; }
    public string State { get; }
    public string InstructionPointer { get; }
    public string Mode { get; }
    public string Priority { get; }
    public ulong JumpAddress { get; }
    public ulong Cr3 { get; }
    public ulong TidValue { get; }
    public ulong PidValue { get; }
    public string Image { get; }
}

internal sealed class StackRow
{
    public StackRow(string index, string childSp, string returnAddress, string symbol, ulong instructionAddress)
    {
        Index = index;
        ChildSp = childSp;
        ReturnAddress = returnAddress;
        Symbol = symbol;
        InstructionAddress = instructionAddress;
    }

    public string Index { get; }
    public string ChildSp { get; }
    public string ReturnAddress { get; }
    public string Symbol { get; }
    public ulong InstructionAddress { get; }
}

internal sealed class MemoryRow
{
    public MemoryRow(string address, string hex, string ascii)
    {
        Address = address;
        Hex = hex;
        Ascii = ascii;
    }

    public string Address { get; }
    public string Hex { get; }
    public string Ascii { get; }
}

internal sealed class DisassemblyRow
{
    public DisassemblyRow(string address, string bytes, string text, string symbol, ulong addressValue)
    {
        Address = address;
        Bytes = bytes;
        Text = text;
        Symbol = symbol;
        AddressValue = addressValue;
    }

    public string Address { get; }
    public string Bytes { get; }
    public string Text { get; }
    public string Symbol { get; }
    public ulong AddressValue { get; }
}

internal sealed class MemoryPage
{
    public MemoryPage(ulong address, ulong cr3, byte[] bytes)
    {
        Address = address;
        Cr3 = cr3;
        Bytes = bytes;
    }

    public ulong Address { get; }
    public ulong Cr3 { get; }
    public byte[] Bytes { get; }
}
