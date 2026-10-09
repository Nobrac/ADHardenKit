namespace ADHardenKit.Gui.Models;

/// <summary>A step of the recommended rollout, as the README describes it.</summary>
public sealed record RolloutStep(
    int Number,
    string Key,
    string Title,
    string Summary,
    string Why,
    EngineMode Mode,
    IReadOnlyList<string> Areas,
    string Level = "Audit",
    bool IsWait = false);

public static class Rollout
{
    public static readonly IReadOnlyList<string> AllAreas =
        ["Logging", "Signing", "Protocols", "CredentialProtection", "LegacyAuth", "PolicyIntegrity", "Services", "LOLBins"];

    public static readonly IReadOnlyList<string> DefaultAreas =
        ["Signing", "LegacyAuth", "CredentialProtection", "Protocols", "PolicyIntegrity", "Logging", "Services"];

    public static readonly IReadOnlyList<RolloutStep> Steps =
    [
        new(1, "logging", "Turn on logging",
            "Deploy the Logging group.",
            "It only changes what is recorded, never what is allowed - nothing can stop working. Every later scan depends on it.",
            EngineMode.Deploy, ["Logging"]),
        new(2, "scan", "First scan",
            "Read what the domain is doing today.",
            "Unsigned LDAP binds, NTLM use, RC4-only accounts and the current settings on every domain controller. Read-only.",
            EngineMode.Scan, DefaultAreas),
        new(3, "wait", "Let the logs fill",
            "Wait a few weeks, then scan again.",
            "The client that binds unsigned only at month-end is the one you would otherwise miss.",
            EngineMode.Scan, DefaultAreas, IsWait: true),
        new(4, "signing", "Signing, observing",
            "Deploy the Signing group at level Audit.",
            "LDAP signing negotiates and channel binding applies where supported. Nothing is required yet.",
            EngineMode.Deploy, ["Signing"]),
        new(5, "protocols", "Legacy protocols",
            "Deploy the Protocols group.",
            "LLMNR, NetBIOS, SMBv1 and WinRM hardening. Check the scan for SMBv1 use first.",
            EngineMode.Deploy, ["Protocols"]),
        new(6, "credentials", "Credential protection",
            "Deploy the CredentialProtection group.",
            "LSA protection and Credential Guard need a reboot. Try one server first and check System log events 3033 and 3063.",
            EngineMode.Deploy, ["CredentialProtection"]),
        new(7, "legacyauth", "Legacy authentication, observing",
            "Deploy the LegacyAuth group at level Audit.",
            "Outgoing NTLM is audited, not denied. The scan then shows who still depends on it.",
            EngineMode.Deploy, ["LegacyAuth"]),
        new(8, "clean", "Scan until clean",
            "Scan, fix what it finds, repeat.",
            "This is the actual work: replace or reconfigure every client the scan names. No tool can do it for you.",
            EngineMode.Scan, DefaultAreas),
        new(9, "enforce", "Enforce, one group at a time",
            "Deploy one group at level Enforce.",
            "Never all at once - when something breaks you want to know which group did it. The engine scans first and stops if something still depends on the old behaviour.",
            EngineMode.Deploy, ["Signing"], Level: "Enforce"),
    ];

    public static readonly IReadOnlyDictionary<string, string> AreaDescriptions = new Dictionary<string, string>
    {
        ["Logging"] = "Advanced audit policy, NTLM and LDAP bind diagnostics, PowerShell logging, larger event logs. Records only - enforces nothing.",
        ["Signing"] = "LDAP signing and channel binding, SMB signing and its audit, Netlogon secure channel.",
        ["Protocols"] = "LLMNR, mDNS and NetBIOS poisoning, SMBv1 and old dialects, Point and Print, legacy TLS and ciphers, WinRM.",
        ["CredentialProtection"] = "LSA protection, Credential Guard, credential caching, anonymous access, Remote Desktop.",
        ["LegacyAuth"] = "NTLM restriction and version, Kerberos encryption types and armoring, certificate mapping.",
        ["PolicyIntegrity"] = "UNC hardened paths for SYSVOL and NETLOGON, policy reapplication even when unchanged.",
        ["Services"] = "Print Spooler on domain controllers and the WebDAV redirector.",
        ["LOLBins"] = "Outbound firewall blocks for living-off-the-land binaries. Opt-in.",
    };
}
