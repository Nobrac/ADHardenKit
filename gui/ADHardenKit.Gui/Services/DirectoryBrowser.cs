using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;

namespace ADHardenKit.Gui.Services;

/// <summary>Read-only lookups for the wizard: the current domain and its organisational units.</summary>
public static class DirectoryBrowser
{
    public static string? CurrentDomain()
    {
        try
        {
            using var domain = Domain.GetComputerDomain();
            return domain.Name;
        }
        catch (ActiveDirectoryObjectNotFoundException)
        {
            return null;
        }
        catch (ActiveDirectoryOperationException)
        {
            return null;
        }
    }

    /// <summary>Every OU's distinguished name, sorted by its path from the domain root.</summary>
    public static Task<IReadOnlyList<string>> GetOrganizationalUnitsAsync(CancellationToken cancellationToken) => Task.Run<IReadOnlyList<string>>(() =>
    {
        using var root = new DirectoryEntry("LDAP://RootDSE");
        var defaultNc = root.Properties["defaultNamingContext"].Value as string;
        if (string.IsNullOrEmpty(defaultNc)) return [];

        using var searchRoot = new DirectoryEntry("LDAP://" + defaultNc);
        using var searcher = new DirectorySearcher(searchRoot, "(objectClass=organizationalUnit)", ["distinguishedName"])
        {
            PageSize = 500,
            SearchScope = SearchScope.Subtree,
        };
        var list = new List<string>();
        using (var results = searcher.FindAll())
        {
            foreach (SearchResult r in results)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (r.Properties["distinguishedName"] is { Count: > 0 } p && p[0] is string dn) list.Add(dn);
            }
        }
        // Sorted by the path read from the root (DC=...,OU=Servers,OU=Tier1) so siblings group.
        return list.OrderBy(dn => string.Join(",", dn.Split(',').Reverse()), StringComparer.OrdinalIgnoreCase).ToList();
    }, cancellationToken);
}
