using System.Collections.ObjectModel;
using System.IO;
using ADHardenKit.Gui.Models;
using ADHardenKit.Gui.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;

namespace ADHardenKit.Gui.ViewModels;

public sealed partial class RolloutItem(RolloutStep step) : ObservableObject
{
    public RolloutStep Step { get; } = step;

    [ObservableProperty] private bool _isDone;
    [ObservableProperty] private bool _isNext;
    [ObservableProperty] private bool _isSelected;
    [ObservableProperty] private string? _doneText;
}

public sealed partial class StartViewModel : StepViewModel
{
    public StartViewModel(MainViewModel owner) : base(owner, "Start", "Where you are in the rollout")
    {
        foreach (var s in Rollout.Steps) Items.Add(new RolloutItem(s));
    }

    public ObservableCollection<RolloutItem> Items { get; } = [];

    [ObservableProperty] private RolloutItem? _recommended;
    [ObservableProperty] private string? _engineError;
    [ObservableProperty] private string _loadingText = "Loading the baseline...";
    [ObservableProperty] private bool _catalogLoaded;
    [ObservableProperty] private string? _catalogSummary;
    [ObservableProperty] private string? _lastScanText;
    [ObservableProperty] private bool _isScanSelected;
    [ObservableProperty] private bool _isCustomSelected;

    public override bool CanGoNext => base.CanGoNext && CatalogLoaded && Owner.Journey is not null;

    public override string NextLabel => Owner.Journey is { } j ? $"Start: {j.Title}" : "Next";

    bool _loaded;

    public override async Task OnEnterAsync()
    {
        if (!_loaded)
        {
            _loaded = true;
            // The rollout state has to be known before the next step is picked, or a domain that
            // is halfway through would start at step 1 again.
            Owner.Domain = DirectoryBrowser.CurrentDomain();
            if (Owner.Domain is not null) Owner.State = RolloutStore.Load(Owner.Domain);
            RefreshRollout();
        }
        else
        {
            RefreshRollout();
            return;
        }

        var script = EngineLocator.Find();
        if (script is null)
        {
            EngineError = $"{EngineLocator.ScriptName} was not found next to this program. Keep both in the same folder, or locate the script.";
            LoadingText = "";
            return;
        }
        await LoadEngineAsync(script);
    }

    async Task LoadEngineAsync(string script)
    {
        EngineError = null;
        IsBusy = true;
        LoadingText = "Loading the baseline...";
        try
        {
            var runner = new EngineRunner(script);
            var catalog = await runner.LoadCatalogAsync(CancellationToken.None);
            Owner.Runner = runner;
            Owner.Catalog = catalog;
            var settings = catalog.Settings.Where(s => !s.IsFirewallRule).ToList();
            CatalogSummary = $"Engine {catalog.Version} - {settings.Count} settings in {settings.Select(s => s.Topic).Distinct().Count()} topics, " +
                             $"{settings.Count(s => s.Staged)} of them staged, plus {catalog.Settings.Count(s => s.IsFirewallRule)} LOLBin firewall entries.";
            CatalogLoaded = true;
            LoadingText = "";
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or IOException or System.Text.Json.JsonException)
        {
            EngineError = ex.Message;
            LoadingText = "";
        }
        finally
        {
            IsBusy = false;
            RefreshNavigation();
        }
    }

    [RelayCommand]
    private async Task LocateEngine()
    {
        var dialog = new OpenFileDialog { Filter = $"{EngineLocator.ScriptName}|{EngineLocator.ScriptName}", Title = "Locate ADHardenKit.ps1" };
        if (dialog.ShowDialog() == true) await LoadEngineAsync(dialog.FileName);
    }

    public void RefreshRollout()
    {
        var state = Owner.State;
        RolloutItem? next = null;
        foreach (var item in Items)
        {
            var done = state.Completed.TryGetValue(item.Step.Key, out var when);
            if (item.Step.Key == "enforce")
            {
                var keys = Rollout.EnforceOrder.Select(e => Rollout.EnforceKey(e.Area)).ToList();
                done = keys.All(state.Completed.ContainsKey);
                when = done ? keys.Max(k => state.Completed[k]) : default;
            }
            // The waiting step is done once a scan ran at least two weeks after the first one.
            if (item.Step.IsWait && state.Completed.TryGetValue("scan", out var first) && state.LastScan is { } last && last - first >= TimeSpan.FromDays(14))
            {
                done = true;
                when = last;
            }
            item.IsDone = done;
            item.DoneText = done ? $"done {when.LocalDateTime:d}" : null;
            item.IsNext = false;
            if (!done && next is null) next = item;
        }
        if (next is not null) next.IsNext = true;
        Recommended = next;

        LastScanText = state.LastScan is { } ls
            ? $"Last scan {ls.LocalDateTime:g}: {state.LastScanFindings ?? 0} finding(s)."
            : "No scan recorded for this domain yet.";

        if (Owner.Journey is null && next is not null) Choose(next);
    }

    [RelayCommand]
    private void Choose(RolloutItem? item)
    {
        if (item is null) return;
        var step = item.Step;
        var areas = step.Areas;
        var profile = step.Profile;
        if (step.Key == "enforce")
        {
            // One group at a time: the first group with staged settings not enforced yet, with the
            // profile its staged settings belong to.
            var (area, p) = Rollout.EnforceOrder.FirstOrDefault(e => !Owner.State.Completed.ContainsKey(Rollout.EnforceKey(e.Area)));
            if (area is not null)
            {
                areas = [area];
                profile = p;
            }
        }
        Owner.BeginJourney(new Journey(step, step.Mode, areas, step.Level, profile));
        foreach (var i in Items) i.IsSelected = i == item;
        IsCustomSelected = false;
        IsScanSelected = false;
        RefreshNavigation();
        Owner.NotifyNextLabel();
    }

    [RelayCommand]
    private void ChooseScan()
    {
        Owner.BeginJourney(new Journey(null, EngineMode.Scan, Rollout.DefaultAreas, "Audit"));
        foreach (var i in Items) i.IsSelected = false;
        IsCustomSelected = false;
        IsScanSelected = true;
        RefreshNavigation();
        Owner.NotifyNextLabel();
    }

    [RelayCommand]
    private void ChooseCustom()
    {
        Owner.BeginJourney(new Journey(null, EngineMode.Deploy, Rollout.DefaultAreas, "Audit"));
        foreach (var i in Items) i.IsSelected = false;
        IsScanSelected = false;
        IsCustomSelected = true;
        RefreshNavigation();
        Owner.NotifyNextLabel();
    }
}
