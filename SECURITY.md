# Sicherheit / Security

## Schwachstelle melden / Reporting a vulnerability

Bitte **kein öffentliches Issue**. Melden Sie Sicherheitslücken vertraulich:

- über GitHub: [Private vulnerability report](https://github.com/ict-baden/vitrine/security/advisories/new)
- per E-Mail: [security@ict-baden.de](mailto:security@ict-baden.de) – wie wir mit Meldungen umgehen, steht auf [ict-baden.de/sicherheit](https://ict-baden.de/sicherheit/)

Please **do not open a public issue**. Report vulnerabilities privately via the link above or by e-mail to [security@ict-baden.de](mailto:security@ict-baden.de); how we handle reports is described at [ict-baden.de/en/security](https://ict-baden.de/en/security/).

Hilfreich sind: betroffene Version, Windows-Version und Anmeldeverfahren, Schritte zum Nachstellen, mögliche Auswirkung. Bitte keine Mandanten- oder Client-IDs, Kontonamen oder echten Protokolldateien beilegen.

Vitrine ist eine Bildschirmsperre. Besonders wichtig sind uns Meldungen, nach denen jemand **ohne berechtigte Anmeldung entsperren** kann, Eingaben während der Sperre **eine Anwendung darunter erreichen**, das Protokoll **unbemerkt verändert** werden kann oder die lokale Schnittstelle (Named Pipe) oder Plugins **mehr erlauben als dokumentiert**. Was Vitrine bewusst nicht verhindert, steht in [docs/limitations.md](docs/limitations.md).

Reports that someone can **unlock without an authorised sign-in**, that input during the lock **reaches an application underneath**, that the audit log can be **changed without detection**, or that the local interface (named pipe) or plugins **allow more than documented** have the highest priority. What Vitrine deliberately does not prevent is listed in [docs/limitations.md](docs/limitations.md).

## Was Sie erwarten können / What to expect

| Schritt | Frist |
|---|---|
| Eingangsbestätigung / Acknowledgement | 3 Werktage / business days |
| Einschätzung / Assessment | 10 Werktage / business days |
| Behebung / Fix | so schnell wie möglich, abhängig von der Schwere / as soon as possible, depending on severity |

Wir veröffentlichen behobene Schwachstellen als GitHub Security Advisory und nennen Sie auf Wunsch als Finder.

## Unterstützte Versionen / Supported versions

Sicherheitsupdates gibt es für die jeweils **neueste veröffentlichte Version**. Kunden mit Supportvertrag erhalten Sicherheitsinformationen vorab.

Security fixes are provided for the **latest released version**.
