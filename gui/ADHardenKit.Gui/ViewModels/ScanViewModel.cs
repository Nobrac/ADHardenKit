using System.Collections.ObjectModel;
using ADHardenKit.Gui.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace ADHardenKit.Gui.ViewModels;

public sealed record FindingGroup(string Title, IReadOnlyList<string> Items);

public sealed partial class ScanViewModel(MainViewModel owner) : RunStepViewModel(owner, "Scan", "What the domain is doing today")
{
    [ObservableProperty] private int _scanDays = 30;
    [ObservableProperty] private int _compliantCount;
    [ObservableProperty] private int _gapCount;
    [ObservableProperty] private int _driftCount;
    [ObservableProperty] private string? _verdict;
    [ObservableProperty] private bool _isClean;

    public ObservableCollection<FindingGroup> Groups { get; } = [];

    // A deployment may go on without a finished scan (it was stopped, or failed on one DC): the
    // scan informs the choices, and an Enforce run repeats it inside the engine anyway.
    public override bool CanGoNext => base.CanGoNext && (ExitCode is 0 or 4 || (HasRun && Owner.Journey?.IsDeploy == true));

    public override string NextLabel => Owner.Journey?.IsDeploy == true ? "Next" : "Finish";

    protected override void ClearRunOutput()
    {
        base.ClearRunOutput();
        Groups.Clear();
        Verdict = null;
        CompliantCount = GapCount = DriftCount = 0;
    }

    public override async Task OnEnterAsync()
    {
        Owner.NotifyNextLabel();
        if (!HasRun && !IsBusy) await RunScan();
    }

    [RelayCommand]
    private async Task RunScan()
    {
        var journey = Owner.Journey;
        var options = new RunOptions
        {
            Mode = EngineMode.Scan,
            Areas = journey?.Mode == EngineMode.Scan ? Rollout.DefaultAreas : journey?.Areas ?? Rollout.DefaultAreas,
            // The current-state comparison targets the values this journey would write: the
            // observing ones before an Audit deployment, the enforcing ones before Enforce. The
            // findings themselves do not depend on it.
            Level = journey?.Level ?? "Audit",
            ScanDays = ScanDays,
        };
        await RunEngineAsync(options, "Scanning - reading event logs and settings on every domain controller...");

        var stateRows = Actions.Where(a => a.Area == "Scan").ToList();
        Owner.CurrentState.Clear();
        foreach (var a in stateRows) Owner.CurrentState[a.Setting] = a;
        CompliantCount = stateRows.Count(a => a.Result == "Compliant");
        GapCount = stateRows.Count(a => a.Result == "Missing");
        DriftCount = stateRows.Count(a => a.Result == "Drift");

        Owner.LastFindings.Clear();
        Owner.LastFindings.AddRange(Findings);
        Groups.Clear();
        foreach (var g in Findings.GroupBy(f => f.Group ?? "General"))
        {
            Groups.Add(new FindingGroup(g.Key, g.Select(f => f.Text).ToList()));
        }

        IsClean = ExitCode == 0 && Findings.Count == 0;
        Verdict = ExitCode switch
        {
            0 => "Nothing found that enforcing would break.",
            4 => $"{Findings.Count} finding(s). Read them before enforcing anything they concern.",
            3 => "The scan could not run - see the log below.",
            null => "The scan did not complete.",
            _ => $"The scan ended with exit code {ExitCode}.",
        };
        StatusText = Verdict;

        if (ExitCode is 0 or 4)
        {
            Owner.RecordScan(Findings.Count, ReportHtml);
            if (Owner.Journey is { IsDeploy: false }) Owner.CompleteJourney();
        }
        RefreshNavigation();
    }
}
