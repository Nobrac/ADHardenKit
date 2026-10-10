using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using ADHardenKit.Gui.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace ADHardenKit.Gui.ViewModels;

/// <summary>A page that runs the engine and shows its output.</summary>
public abstract partial class RunStepViewModel(MainViewModel owner, string title, string subtitle) : StepViewModel(owner, title, subtitle)
{
    CancellationTokenSource? _cts;

    public ObservableCollection<LogLine> Log { get; } = [];
    public ObservableCollection<ActionEvent> Actions { get; } = [];
    public ObservableCollection<FindingEvent> Findings { get; } = [];

    [ObservableProperty] private int? _exitCode;
    [ObservableProperty] private string? _reportHtml;
    [ObservableProperty] private string? _logFile;
    [ObservableProperty] private string? _missingModule;
    [ObservableProperty] private string _statusText = "";
    [ObservableProperty] private bool _hasRun;

    public bool Succeeded => ExitCode == 0;

    public override void Reset()
    {
        base.Reset();
        ClearRunOutput();
    }

    /// <summary>Clears what the previous run produced, keeping the page's own inputs.</summary>
    protected virtual void ClearRunOutput()
    {
        Log.Clear();
        Actions.Clear();
        Findings.Clear();
        ExitCode = null;
        ReportHtml = null;
        LogFile = null;
        MissingModule = null;
        StatusText = "";
        HasRun = false;
    }

    protected async Task<int?> RunEngineAsync(RunOptions options, string runningText)
    {
        if (Owner.Runner is null) return null;

        ClearRunOutput();
        IsBusy = true;
        StatusText = runningText;
        _cts = new CancellationTokenSource();
        CancelCommand.NotifyCanExecuteChanged();

        // Progress<T> captures the UI thread here, so every event lands on it.
        var progress = new Progress<EngineEvent>(OnEvent);
        try
        {
            ExitCode = await Owner.Runner.RunAsync(options.ToArguments(), progress, _cts.Token);
        }
        catch (OperationCanceledException)
        {
            Log.Add(new LogLine("Warning", "Stopped. What the engine had already written stays; nothing else was changed."));
            ExitCode = null;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            Log.Add(new LogLine("Error", "Could not start Windows PowerShell: " + ex.Message));
            ExitCode = null;
        }
        finally
        {
            _cts.Dispose();
            _cts = null;
            IsBusy = false;
            HasRun = true;
            CancelCommand.NotifyCanExecuteChanged();
            OnPropertyChanged(nameof(Succeeded));
        }
        return ExitCode;
    }

    protected virtual void OnEvent(EngineEvent e)
    {
        switch (e)
        {
            case LogEvent l:
                Log.Add(new LogLine(l.Level, l.Message));
                if (l.Level == "Header") StatusText = l.Message;
                break;
            case ActionEvent a when AcceptAction(a):
                Actions.Add(a);
                break;
            case FindingEvent f:
                Findings.Add(f);
                break;
            case ReportEvent r:
                ReportHtml = r.Html;
                LogFile = r.Log;
                break;
            case MissingModuleEvent m:
                MissingModule = m.Module;
                break;
            case RawLineEvent raw:
                Log.Add(new LogLine(raw.IsError ? "Error" : "Raw", raw.Text));
                break;
        }
    }

    /// <summary>
    /// Whether an action belongs on this page. A Deploy at level Enforce runs a scan first, and
    /// those rows describe the domain, not the deployment.
    /// </summary>
    protected virtual bool AcceptAction(ActionEvent action) => true;

    [RelayCommand(CanExecute = nameof(CanCancel))]
    private void Cancel() => _cts?.Cancel();

    private bool CanCancel() => _cts is not null;

    [RelayCommand]
    private void OpenReport()
    {
        if (ReportHtml is not null && File.Exists(ReportHtml)) Process.Start(new ProcessStartInfo(ReportHtml) { UseShellExecute = true });
    }

    [RelayCommand]
    private void OpenLogFolder()
    {
        var folder = LogFile is not null ? Path.GetDirectoryName(LogFile) : null;
        if (folder is not null && Directory.Exists(folder)) Process.Start(new ProcessStartInfo(folder) { UseShellExecute = true });
    }
}
