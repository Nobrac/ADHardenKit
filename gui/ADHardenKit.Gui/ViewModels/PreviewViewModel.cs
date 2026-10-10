using ADHardenKit.Gui.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace ADHardenKit.Gui.ViewModels;

public sealed partial class PreviewViewModel(MainViewModel owner) : RunStepViewModel(owner, "Preview", "Every change, before anything is written")
{
    [ObservableProperty] private int _plannedCount;
    [ObservableProperty] private int _compliantCount;
    [ObservableProperty] private int _skippedCount;
    [ObservableProperty] private int _failedCount;
    [ObservableProperty] private int _warningCount;
    [ObservableProperty] private RunOptions? _previewedOptions;

    /// <summary>At level Enforce: what the engine's own scan says this run would break.</summary>
    public System.Collections.ObjectModel.ObservableCollection<FindingEvent> BlockingFindings { get; } = [];

    protected override bool AcceptAction(ActionEvent action) => action.Area != "Scan";

    public override bool CanGoNext => base.CanGoNext && Succeeded && PlannedCount > 0;

    public override string NextLabel => "Continue to deploy";

    public override async Task OnEnterAsync()
    {
        Owner.NotifyNextLabel();
        // Re-plan whenever the choices changed since the last preview, so what is deployed is
        // always exactly what was previewed.
        var options = Owner.BuildOptions(EngineMode.Deploy);
        if (!IsBusy && (!HasRun || options.ToCommandLine() != PreviewedOptions?.ToCommandLine())) await RunPreview();
    }

    [RelayCommand]
    private async Task RunPreview()
    {
        var options = Owner.BuildOptions(EngineMode.Deploy);
        await RunEngineAsync(options, "Planning - comparing every setting with what the GPOs hold today...");
        PreviewedOptions = options;
        BlockingFindings.Clear();
        foreach (var f in Findings.Where(f => f.Group is not null && options.Areas.Contains(f.Group))) BlockingFindings.Add(f);
        PlannedCount = Actions.Count(a => a.Result == "Planned");
        CompliantCount = Actions.Count(a => a.Result == "Compliant");
        SkippedCount = Actions.Count(a => a.Result == "Skipped");
        FailedCount = Actions.Count(a => a.Result == "Failed");
        WarningCount = Log.Count(l => l.Level == "Warning");
        StatusText = ExitCode switch
        {
            0 when PlannedCount == 0 => "Nothing to change - every setting in scope is already in place.",
            0 => $"{PlannedCount} change(s) planned, {CompliantCount} already in place. Nothing has been written.",
            null => "The preview did not complete.",
            _ => $"The preview ended with exit code {ExitCode} - see the log below.",
        };
        RefreshNavigation();
    }
}
