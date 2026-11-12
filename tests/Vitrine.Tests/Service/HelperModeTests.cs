// SPDX-License-Identifier: MIT
using Vitrine.Core.Service;

namespace Vitrine.Tests.Service;

public sealed class HelperModeTests
{
    [Theory]
    [InlineData(new string[0], HelperKind.None, 0)]
    [InlineData(new[] { "--settings" }, HelperKind.None, 0)]
    [InlineData(new[] { "--agent", "--lock" }, HelperKind.None, 0)]
    [InlineData(new[] { "--service" }, HelperKind.Service, 0)]
    [InlineData(new[] { " --SERVICE " }, HelperKind.Service, 0)]
    [InlineData(new[] { "--watchdog", "1234" }, HelperKind.Watchdog, 1234)]
    [InlineData(new[] { "--Watchdog", " 42 " }, HelperKind.Watchdog, 42)]
    // Dienst geht vor, wie bisher in App.OnStartup
    [InlineData(new[] { "--watchdog", "7", "--service" }, HelperKind.Service, 0)]
    public void Detects_helper_processes(string[] args, HelperKind kind, int pid)
    {
        var m = HelperMode.Detect(args);
        Assert.Equal(kind, m.Kind);
        Assert.Equal(pid, m.WatchdogPid);
    }

    [Theory]
    [InlineData("--watchdog")]
    [InlineData("--watchdog", "abc")]
    [InlineData("--watchdog", "--settings")]
    [InlineData("--watchdog", "1e3")]
    public void Watchdog_without_valid_pid_starts_the_normal_app(params string[] args)
    {
        // Wie vorher: ohne gültige Prozessnummer kein Wächter, sondern die normale App (mit Einzelinstanz-Prüfung)
        Assert.Equal(HelperKind.None, HelperMode.Detect(args).Kind);
    }
}
