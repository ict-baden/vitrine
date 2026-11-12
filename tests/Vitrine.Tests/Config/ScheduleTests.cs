// SPDX-License-Identifier: MIT
using System.Globalization;
using Vitrine.Core.Config;

namespace Vitrine.Tests.Config;

public sealed class ScheduleTests
{
    [Theory]
    [InlineData("18:00", "18:00", new DayOfWeek[0])]
    [InlineData(" 7:30 @ Mo, Di ,Fr", "7:30", new[] { DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Friday })]
    [InlineData("07:30@Mon,Tue,mon", "07:30", new[] { DayOfWeek.Monday, DayOfWeek.Tuesday })]
    [InlineData("06:00@Saturday,So", "06:00", new[] { DayOfWeek.Saturday, DayOfWeek.Sunday })]
    [InlineData("18.00", "18:00", new DayOfWeek[0])]
    [InlineData("18:00@Mo-Fr", "18:00", new[] { DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday })]
    [InlineData("18:00@Mon - Wed, Sat", "18:00", new[] { DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Saturday })]
    [InlineData("22:00@Fr-Mo", "22:00", new[] { DayOfWeek.Friday, DayOfWeek.Saturday, DayOfWeek.Sunday, DayOfWeek.Monday })]
    public void Liest_Zeit_und_Tage(string text, string time, DayOfWeek[] days)
    {
        var e = Schedule.Parse(text);
        Assert.NotNull(e);
        Assert.Equal(time, e!.Time);
        Assert.Equal(days, e.Days);
    }

    [Theory]
    [InlineData("25:00")]
    [InlineData("abends")]
    [InlineData("")]
    [InlineData("6:30 PM")]
    public void Ungueltige_Zeit_ergibt_null(string text) => Assert.Null(Schedule.Parse(text));

    [Theory]
    [InlineData("06:00@1,Xyz")]
    [InlineData("18:00@Mo-Fx")]
    [InlineData("18:00@")]
    [InlineData("@Mon-Fri")]
    [InlineData("18:00@Montag bis Freitag")]
    public void Unlesbare_Tage_ergeben_null_statt_jeden_Tag(string text) => Assert.Null(Schedule.Parse(text));

    [Fact]
    public void Tage_in_der_Sprache_der_Oberflaeche_hin_und_zurueck()
    {
        var fr = CultureInfo.GetCultureInfo("fr-FR");
        var e = new ScheduleEntry { Time = "18:00", Days = [DayOfWeek.Monday, DayOfWeek.Wednesday] };
        var text = Schedule.Format(e, fr);
        Assert.DoesNotContain("Mon", text);
        var back = Schedule.Parse(text, fr);
        Assert.Equal(e.Days, back!.Days);

        var de = CultureInfo.GetCultureInfo("de-DE");
        Assert.Equal([DayOfWeek.Monday, DayOfWeek.Sunday], Schedule.Parse("18:00@Mo,So", de)!.Days);
        Assert.Equal("18:00@Mon,Wed", Schedule.Format(e));
    }

    [Fact]
    public void Faellig_einmal_pro_Tag_in_der_Minute_ab_der_Uhrzeit()
    {
        var entries = new List<ScheduleEntry> { new() { Time = "18:00" } };
        var fired = new HashSet<string>();
        Assert.Null(Schedule.Due(new DateTime(2026, 10, 19, 17, 59, 59), entries, fired));
        Assert.NotNull(Schedule.Due(new DateTime(2026, 10, 19, 18, 0, 10), entries, fired));
        Assert.Null(Schedule.Due(new DateTime(2026, 10, 19, 18, 0, 20), entries, fired)); // schon ausgelöst
        fired.Clear();
        Assert.Null(Schedule.Due(new DateTime(2026, 10, 19, 18, 1, 0), entries, fired)); // Minute vorbei
    }

    [Fact]
    public void Faellig_nur_an_den_genannten_Tagen()
    {
        var entries = new List<ScheduleEntry> { new() { Time = "07:30", Days = [DayOfWeek.Monday] } };
        Assert.Null(Schedule.Due(new DateTime(2026, 10, 20, 7, 30, 0), entries, new HashSet<string>())); // Dienstag
        Assert.NotNull(Schedule.Due(new DateTime(2026, 10, 19, 7, 30, 0), entries, new HashSet<string>())); // Montag
    }
}
