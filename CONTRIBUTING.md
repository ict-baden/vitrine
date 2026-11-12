# Mitmachen / Contributing

Danke für Ihr Interesse! Thank you for your interest!

## Vor größeren Änderungen / Before larger changes

Bitte erst ein Issue anlegen und den Plan kurz beschreiben. So vermeiden wir doppelte Arbeit.
Please open an issue first and describe your plan.

## Pull Requests

- Ein Thema pro Pull Request, mit Tests.
- `dotnet build Vitrine.sln` und `dotnet test Vitrine.sln` müssen grün sein; unter Linux und macOS `dotnet test tests/Vitrine.Tests -f net10.0` (nur der plattformneutrale Teil). Einzelheiten in [`docs/development.md`](docs/development.md).
- **Tests sperren nie den Rechner und ändern nichts am System:** keine Low-Level-Hooks, kein `LockWorkStation`, keine Schreibzugriffe unter `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies` oder `HKLM`, keine Anmeldeversuche mit echten Konten. Die Logik dafür liegt in `Vitrine.Core` und wird mit Attrappen getestet.
- Änderungen am Sicherheitsverhalten (wer entsperren darf, was während der Sperre durchkommt, Protokoll, Schnittstelle, Plugins) nur mit Test und Eintrag in [`CHANGELOG.md`](CHANGELOG.md).
- Texte der Oberfläche nur in `.resx` (en, de, es, fr, zh-Hans), siehe [`CLAUDE.md`](CLAUDE.md).
- Keine neuen Abhängigkeiten ohne Rücksprache. Nur freizügige Lizenzen (MIT, BSD, Apache-2.0, ISC), keine GPL/AGPL. Jede neue oder aktualisierte Abhängigkeit gehört mit Version, Quelle, Copyright und Lizenztext in [`THIRD-PARTY-NOTICES.txt`](THIRD-PARTY-NOTICES.txt).
- Keine Passwörter, Mandanten- oder Client-IDs, internen Hostnamen oder Kundendaten in Code, Tests oder Screenshots. Screenshots ohne echte Personennamen.

## Developer Certificate of Origin (DCO)

Mit jedem Commit bestätigen Sie, dass Sie den Beitrag unter der Lizenz dieses Projekts (MIT) einbringen dürfen ([developercertificate.org](https://developercertificate.org/)). Dafür jeden Commit mit `-s` erstellen:

By contributing you certify the [DCO](https://developercertificate.org/). Sign off every commit:

```
git commit -s -m "Fehler beim Lesen leerer Dateien behoben"
```

Das fügt `Signed-off-by: Name <E-Mail>` hinzu.
