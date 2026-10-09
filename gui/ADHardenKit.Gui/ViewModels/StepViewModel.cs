using System.ComponentModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace ADHardenKit.Gui.ViewModels;

/// <summary>A page of the wizard.</summary>
public abstract partial class StepViewModel(MainViewModel owner, string title, string subtitle) : ObservableObject
{
    public MainViewModel Owner { get; } = owner;
    public string Title { get; } = title;
    public string Subtitle { get; } = subtitle;

    [ObservableProperty] private int _number;
    [ObservableProperty] private bool _isActive;
    [ObservableProperty] private bool _isDone;
    [ObservableProperty] private bool _isSkipped;
    [ObservableProperty] private bool _isBusy;

    /// <summary>Whether the Next button is enabled on this page.</summary>
    public virtual bool CanGoNext => !IsBusy;

    public virtual string NextLabel => "Next";

    /// <summary>Called each time the page is shown.</summary>
    public virtual Task OnEnterAsync() => Task.CompletedTask;

    /// <summary>Forgets results when the journey changes, so a page never shows a stale run.</summary>
    public virtual void Reset() => IsDone = false;

    protected void RefreshNavigation() => OnPropertyChanged(nameof(CanGoNext));

    protected override void OnPropertyChanged(PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (e.PropertyName is nameof(CanGoNext) or nameof(IsBusy))
        {
            if (e.PropertyName == nameof(IsBusy)) base.OnPropertyChanged(new PropertyChangedEventArgs(nameof(CanGoNext)));
            Owner.RefreshNavigation();
        }
    }
}
