using ADHardenKit.Gui.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace ADHardenKit.Gui.ViewModels;

public sealed partial class DeployViewModel(MainViewModel owner) : RunStepViewModel(owner, "Deploy", "Write the GPOs")
{
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(DeployNowCommand))]
    private bool _reviewed;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(DeployNowCommand))]
    private string _confirmDomain = "";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ForceDeployCommand))]
    private bool _forceAcknowledged;

    [ObservableProperty] private bool _blocked;

    /// <summary>The findings that stopped the run: those about the groups being enforced, not informational ones.</summary>
    public System.Collections.ObjectModel.ObservableCollection<FindingEvent> BlockingFindings { get; } = [];

    public bool IsEnforce => Owner.Preview.PreviewedOptions?.Level == "Enforce";

    /// <summary>Enforce asks for the domain name to be typed: the one run that can break logons gets a deliberate step.</summary>
    public bool NeedsDomainConfirmation => IsEnforce && Owner.Domain is not null;

    public string Summary => Owner.Preview.PreviewedOptions is { } o
        ? $"{Owner.Preview.PlannedCount} change(s) in {string.Join(", ", o.Areas)} - profile {o.Profile}, level {o.Level}" +
          (o.MemberServerOu is null ? ", member GPOs left unlinked." : $", member GPOs linked to {o.MemberServerOu}.")
        : "";

    public override bool CanGoNext => base.CanGoNext && Succeeded;

    public override string NextLabel => "Finish";

    public override void Reset()
    {
        base.Reset();
        Reviewed = false;
        ConfirmDomain = "";
        ForceAcknowledged = false;
        Blocked = false;
    }

    public override Task OnEnterAsync()
    {
        Owner.NotifyNextLabel();
        OnPropertyChanged(nameof(IsEnforce));
        OnPropertyChanged(nameof(NeedsDomainConfirmation));
        OnPropertyChanged(nameof(Summary));
        DeployNowCommand.NotifyCanExecuteChanged();
        return Task.CompletedTask;
    }

    [RelayCommand(CanExecute = nameof(CanDeploy))]
    private Task DeployNow() => RunDeploy(force: false);

    private bool CanDeploy() => !IsBusy && Reviewed && !Succeeded &&
        (!NeedsDomainConfirmation || string.Equals(ConfirmDomain.Trim(), Owner.Domain, StringComparison.OrdinalIgnoreCase));

    [RelayCommand(CanExecute = nameof(CanForce))]
    private Task ForceDeploy() => RunDeploy(force: true);

    private bool CanForce() => !IsBusy && Blocked && ForceAcknowledged;

    async Task RunDeploy(bool force)
    {
        var planned = Owner.Preview.PreviewedOptions;
        if (planned is null) return;
        await RunEngineAsync(planned with { Apply = true, Force = force }, "Deploying - writing the GPOs...");
        Blocked = ExitCode == 4;
        BlockingFindings.Clear();
        foreach (var f in Findings.Where(f => f.Group is not null && planned.Areas.Contains(f.Group))) BlockingFindings.Add(f);
        StatusText = ExitCode switch
        {
            0 => "Deployed.",
            1 => "Deployed with failures - the report lists each one.",
            4 => "Not deployed: the scan found something that still depends on what this run would enforce.",
            3 => "Not deployed: a prerequisite failed.",
            null => "The deployment was stopped.",
            _ => $"The engine ended with exit code {ExitCode}.",
        };
        if (ExitCode == 0) Owner.CompleteJourney();
        DeployNowCommand.NotifyCanExecuteChanged();
        ForceDeployCommand.NotifyCanExecuteChanged();
        RefreshNavigation();
    }
}
