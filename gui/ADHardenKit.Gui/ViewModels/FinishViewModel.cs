using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace ADHardenKit.Gui.ViewModels;

public sealed partial class FinishViewModel(MainViewModel owner) : StepViewModel(owner, "Done", "Report and what comes next")
{
    [ObservableProperty] private string _headline = "";
    [ObservableProperty] private RunStepViewModel? _lastRun;

    public ObservableCollection<string> NextSteps { get; } = [];

    public override string NextLabel => "Back to the rollout";

    public override Task OnEnterAsync()
    {
        Owner.NotifyNextLabel();
        var journey = Owner.Journey;
        NextSteps.Clear();
        if (journey is { IsDeploy: true })
        {
            LastRun = Owner.Deploy;
            Headline = Owner.Deploy.StatusText;
            NextSteps.Add("Run gpupdate /force on one domain controller and one member server, or wait for the next policy refresh.");
            NextSteps.Add("Verify on a member server with Verify-MemberDeployment.ps1, and the Logging group with Verify-LoggingDeployment.ps1.");
            var options = Owner.Preview.PreviewedOptions;
            var reboot = Owner.Configure.Topics.Where(t => t.IsIncluded && t.NeedsReboot).Select(t => t.Name).ToList();
            if (reboot.Count > 0) NextSteps.Add("Needs a reboot to take effect: " + string.Join(", ", reboot) + ". Start with one server.");
            if (options?.MemberServerOu is null) NextSteps.Add("The member server GPOs are not linked yet. Run again with a member server OU when you are ready.");
            if (options?.Level == "Audit") NextSteps.Add("Staged settings are observing. Scan again after a few weeks before enforcing them.");
        }
        else
        {
            LastRun = Owner.Scan;
            Headline = Owner.Scan.Verdict ?? "";
            NextSteps.Add(Owner.Scan.Findings.Count > 0
                ? "Work through the findings in the report: each names the client, account or server to fix."
                : "Nothing blocks enforcement in the scanned groups. Keep scanning until the logs cover a full business cycle.");
        }

        if (Owner.Start.Recommended is { } next)
        {
            NextSteps.Add($"Next in the rollout: step {next.Step.Number}, {next.Step.Title}. {next.Step.Summary}");
        }
        return Task.CompletedTask;
    }
}
