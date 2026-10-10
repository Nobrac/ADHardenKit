using ADHardenKit.Gui.Models;
using CommunityToolkit.Mvvm.Input;

namespace ADHardenKit.Gui.ViewModels;

public sealed partial class CheckViewModel(MainViewModel owner) : RunStepViewModel(owner, "Check", "Modules, rights and connectivity")
{
    public override bool CanGoNext => base.CanGoNext && Succeeded;

    public string? InstallServer => MissingModule is null ? null : "Install-WindowsFeature RSAT-AD-PowerShell, GPMC";

    public string? InstallClient => MissingModule is null ? null
        : "Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0\r\nAdd-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0";

    public override async Task OnEnterAsync()
    {
        if (!HasRun && !IsBusy) await RunCheck();
    }

    [RelayCommand]
    private async Task RunCheck()
    {
        await RunEngineAsync(new RunOptions { Mode = EngineMode.Check }, "Checking prerequisites...");
        StatusText = ExitCode switch
        {
            0 => "Everything the engine needs is in place.",
            3 when MissingModule is not null => $"The {MissingModule} module is missing on this machine.",
            3 => "A prerequisite is not met - the lines marked in red say which.",
            null => "The check did not complete.",
            _ => $"The check ended with exit code {ExitCode}.",
        };
        OnPropertyChanged(nameof(InstallServer));
        OnPropertyChanged(nameof(InstallClient));
        RefreshNavigation();
    }

    [RelayCommand]
    private static void Copy(string? text)
    {
        if (!string.IsNullOrEmpty(text)) System.Windows.Clipboard.SetText(text);
    }
}
