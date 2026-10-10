using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using ADHardenKit.Gui.Models;

namespace ADHardenKit.Gui.Services;

/// <summary>
/// Runs ADHardenKit.ps1 in Windows PowerShell 5.1 - the engine needs the GroupPolicy module,
/// which is a Windows PowerShell module - and turns its -EventStream output into events.
/// </summary>
public sealed class EngineRunner(string scriptPath, string? powerShellPath = null)
{
    const string Prefix = "@@ADHK ";

    /// <summary>Windows PowerShell 5.1, unless a different host is given (the tests use pwsh).</summary>
    public string PowerShellPath { get; } = powerShellPath
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe");

    public static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public string ScriptPath { get; } = scriptPath;

    public async Task<int> RunAsync(IEnumerable<EngineArgument> arguments, IProgress<EngineEvent> progress, CancellationToken cancellationToken)
    {
        // -EncodedCommand rather than -File: with -File every value arrives as one string, so
        // -Area Signing,Logging would bind as a single invalid group. The encoded command is
        // PowerShell source in which every value is a single-quoted literal.
        var command = "& " + RunOptions.Quote(ScriptPath) + " " + RunOptions.Render(arguments) + " -EventStream; exit $LASTEXITCODE";
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(command));

        var psi = new ProcessStartInfo
        {
            FileName = PowerShellPath,
            WorkingDirectory = Path.GetDirectoryName(ScriptPath)!,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded })
        {
            psi.ArgumentList.Add(a);
        }

        using var process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        process.Start();
        // Nothing is ever typed into the engine; closing stdin makes any stray prompt fail fast
        // instead of hanging the run.
        process.StandardInput.Close();

        using var registration = cancellationToken.Register(() =>
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
        });

        var stdout = PumpAsync(process.StandardOutput, progress, isError: false);
        var stderr = PumpAsync(process.StandardError, progress, isError: true);
        await Task.WhenAll(stdout, stderr).ConfigureAwait(false);
        await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return process.ExitCode;
    }

    /// <summary>Runs -Mode Catalog and returns the baseline.</summary>
    public async Task<Catalog> LoadCatalogAsync(CancellationToken cancellationToken)
    {
        Catalog? catalog = null;
        var errors = new StringBuilder();
        var progress = new SyncProgress(e =>
        {
            if (e is CatalogEvent c) catalog = c.Catalog;
            else if (e is RawLineEvent { IsError: true } r) errors.AppendLine(r.Text);
        });
        var exit = await RunAsync([new EngineArgument("Mode", ["Catalog"])], progress, cancellationToken).ConfigureAwait(false);
        return catalog ?? throw new InvalidOperationException(
            $"The engine did not return its catalog (exit code {exit}). {errors.ToString().Trim()}");
    }

    static async Task PumpAsync(StreamReader reader, IProgress<EngineEvent> progress, bool isError)
    {
        while (await reader.ReadLineAsync().ConfigureAwait(false) is { } line)
        {
            var e = Parse(line, isError);
            if (e is not null) progress.Report(e);
        }
    }

    public static EngineEvent? Parse(string line, bool isError = false)
    {
        if (!line.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return string.IsNullOrWhiteSpace(line) ? null : new RawLineEvent(line, isError);
        }

        try
        {
            using var doc = JsonDocument.Parse(line.AsMemory(Prefix.Length));
            var root = doc.RootElement;
            string? S(string name) => root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

            return S("type") switch
            {
                "log" => new LogEvent(S("level") ?? "Info", S("message") ?? ""),
                "action" => new ActionEvent(S("area") ?? "", S("setting") ?? "", S("target") ?? "", S("result") ?? "", S("severity") ?? "Info", S("detail")),
                "finding" => new FindingEvent(S("group"), S("text") ?? ""),
                "report" => new ReportEvent(S("html"), S("json"), S("log")),
                "missingModule" => new MissingModuleEvent(S("module") ?? ""),
                "catalog" => new CatalogEvent(root.GetProperty("data").Deserialize<Catalog>(JsonOptions)!),
                _ => new RawLineEvent(line, isError),
            };
        }
        catch (JsonException)
        {
            return new RawLineEvent(line, isError);
        }
    }

    /// <summary>An IProgress that calls back on the reporting thread, for collecting results.</summary>
    sealed class SyncProgress(Action<EngineEvent> handler) : IProgress<EngineEvent>
    {
        public void Report(EngineEvent value) => handler(value);
    }
}
