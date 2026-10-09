using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace ADHardenKit.Gui.ViewModels;

/// <summary>Small value converters used from XAML through x:Static.</summary>
public static class Converters
{
    public static readonly IValueConverter NotNullToVisibility = new Lambda(v => v is null || v is string { Length: 0 } ? Visibility.Collapsed : Visibility.Visible);
    public static readonly IValueConverter NullToVisibility = new Lambda(v => v is null || v is string { Length: 0 } ? Visibility.Visible : Visibility.Collapsed);
    public static readonly IValueConverter InverseBoolToVisibility = new Lambda(v => v is true ? Visibility.Collapsed : Visibility.Visible);
    public static readonly IValueConverter PositiveToVisibility = new Lambda(v => v is int i && i > 0 ? Visibility.Visible : Visibility.Collapsed);
    public static readonly IValueConverter ZeroToVisibility = new Lambda(v => v is int i && i == 0 ? Visibility.Visible : Visibility.Collapsed);

    sealed class Lambda(Func<object?, object> convert) : IValueConverter
    {
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => convert(value);
        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
    }
}
