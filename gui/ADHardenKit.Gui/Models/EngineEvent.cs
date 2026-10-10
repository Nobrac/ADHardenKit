namespace ADHardenKit.Gui.Models;

/// <summary>One '@@ADHK' line from the engine, or a plain output line.</summary>
public abstract record EngineEvent;

public sealed record LogEvent(string Level, string Message) : EngineEvent;

public sealed record ActionEvent(string Area, string Setting, string Target, string Result, string Severity, string? Detail) : EngineEvent;

public sealed record FindingEvent(string? Group, string Text) : EngineEvent;

public sealed record ReportEvent(string? Html, string? Json, string? Log) : EngineEvent;

public sealed record MissingModuleEvent(string Module) : EngineEvent;

public sealed record CatalogEvent(Catalog Catalog) : EngineEvent;

/// <summary>Console text that is not part of the event stream (banners, errors from PowerShell itself).</summary>
public sealed record RawLineEvent(string Text, bool IsError) : EngineEvent;
