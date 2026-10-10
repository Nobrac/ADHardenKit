using System.Collections.ObjectModel;
using ADHardenKit.Gui.Models;
using ADHardenKit.Gui.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace ADHardenKit.Gui.ViewModels;

/// <summary>What the person set out to do: a rollout step, or a run of their own.</summary>
public sealed record Journey(RolloutStep? Step, EngineMode Mode, IReadOnlyList<string> Areas, string Level, string Profile = "Baseline")
{
    public string Title => Step?.Title ?? (Mode == EngineMode.Scan ? "Scan" : "Custom deployment");
    public bool IsDeploy => Mode == EngineMode.Deploy;
}

public partial class MainViewModel : ObservableObject
{
    public MainViewModel()
    {
        Start = new StartViewModel(this);
        Check = new CheckViewModel(this);
        Scan = new ScanViewModel(this);
        Configure = new ConfigureViewModel(this);
        Preview = new PreviewViewModel(this);
        Deploy = new DeployViewModel(this);
        Finish = new FinishViewModel(this);
        Steps = [Start, Check, Scan, Configure, Preview, Deploy, Finish];
        for (var i = 0; i < Steps.Count; i++) Steps[i].Number = i + 1;
        CurrentStep = Start;
    }

    public StartViewModel Start { get; }
    public CheckViewModel Check { get; }
    public ScanViewModel Scan { get; }
    public ConfigureViewModel Configure { get; }
    public PreviewViewModel Preview { get; }
    public DeployViewModel Deploy { get; }
    public FinishViewModel Finish { get; }

    public ObservableCollection<StepViewModel> Steps { get; }

    public string Version => typeof(MainViewModel).Assembly.GetName().Version?.ToString(3) ?? "";

    [ObservableProperty] private StepViewModel _currentStep = null!;
    [ObservableProperty] private EngineRunner? _runner;
    [ObservableProperty] private Catalog? _catalog;
    [ObservableProperty] private string? _domain;
    [ObservableProperty] private RolloutState _state = new();
    [ObservableProperty] private Journey? _journey;

    /// <summary>Current value per setting Id, from the last scan of this session.</summary>
    public Dictionary<string, ActionEvent> CurrentState { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Findings of the last scan of this session, with the group each one gates.</summary>
    public List<FindingEvent> LastFindings { get; } = [];

    public void BeginJourney(Journey journey)
    {
        Journey = journey;
        foreach (var s in Steps.Skip(1)) s.Reset();
        var deploy = journey.IsDeploy;
        Configure.IsSkipped = !deploy;
        Preview.IsSkipped = !deploy;
        Deploy.IsSkipped = !deploy;
        Configure.ApplyJourney(journey);
    }

    public void RefreshNavigation()
    {
        NextCommand.NotifyCanExecuteChanged();
        BackCommand.NotifyCanExecuteChanged();
    }

    partial void OnCurrentStepChanged(StepViewModel? oldValue, StepViewModel newValue)
    {
        if (oldValue is not null) oldValue.IsActive = false;
        newValue.IsActive = true;
        OnPropertyChanged(nameof(NextLabel));
        RefreshNavigation();
        _ = newValue.OnEnterAsync();
    }

    public string NextLabel => CurrentStep.NextLabel;

    public void NotifyNextLabel() => OnPropertyChanged(nameof(NextLabel));

    [RelayCommand(CanExecute = nameof(CanGoNext))]
    private void Next()
    {
        if (CurrentStep == Finish)
        {
            // Back to the rollout with nothing selected, so the start page picks the next step.
            Journey = null;
            GoTo(Start);
            return;
        }
        CurrentStep.IsDone = true;
        var i = Steps.IndexOf(CurrentStep) + 1;
        while (i < Steps.Count && Steps[i].IsSkipped) i++;
        if (i < Steps.Count) GoTo(Steps[i]);
    }

    private bool CanGoNext() => CurrentStep.CanGoNext;

    [RelayCommand(CanExecute = nameof(CanGoBack))]
    private void Back()
    {
        var i = Steps.IndexOf(CurrentStep) - 1;
        while (i > 0 && Steps[i].IsSkipped) i--;
        if (i >= 0) GoTo(Steps[i]);
    }

    private bool CanGoBack() => CurrentStep != Start && CurrentStep != Finish && !CurrentStep.IsBusy;

    public void GoTo(StepViewModel step) => CurrentStep = step;

    /// <summary>Marks the journey's rollout step done and remembers it for this domain.</summary>
    public void CompleteJourney()
    {
        // The waiting step completes by itself (a scan two weeks after the first), and "scan
        // until clean" only when the scan really was clean.
        if (Journey?.Step is { } step && Domain is not null && !step.IsWait && (step.Key != "clean" || Scan.IsClean))
        {
            if (step.Key == "enforce" || Journey.Level == "Enforce")
            {
                // The Enforce step is done group by group; the start page counts it complete once
                // every group with staged settings has been enforced.
                foreach (var area in EnforcedAreas()) State.Completed[Rollout.EnforceKey(area)] = DateTimeOffset.Now;
            }
            else
            {
                State.Completed[step.Key] = DateTimeOffset.Now;
            }
            RolloutStore.Save(State);
        }
        Start.RefreshRollout();
    }

    /// <summary>The groups the last deployment actually enforced, as the preview recorded them.</summary>
    IEnumerable<string> EnforcedAreas() => Preview.PreviewedOptions is { Level: "Enforce" } o ? o.Areas : [];

    public void RecordScan(int findings, string? report)
    {
        if (Domain is null) return;
        State.LastScan = DateTimeOffset.Now;
        State.Completed.TryAdd("scan", DateTimeOffset.Now);
        State.LastScanFindings = findings;
        State.LastReport = report;
        RolloutStore.Save(State);
    }

    public RunOptions BuildOptions(EngineMode mode, bool apply = false, bool force = false) => Configure.BuildOptions(mode, apply, force);
}
