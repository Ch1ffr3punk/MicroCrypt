# MicroCrypt

MicroCrypt – Für diejenigen, die uns am Herzen liegen

## Sicherheitsaspekte

- **Speicher Sicherheit**: MicroCrypt nutzt `memguard`, um sensible Daten
  sicher im gesperrten Speicher abzulegen und so zu verhindern, dass sie
  auf die Festplatte ausgelagert werden oder in Speicherabzügen erscheinen.
 
- **Zwischenablage Handhabung**: Kopierter Text in der Zwischenablage wird
  automatisch nach 15 Sekunden aus dem Zwischenspeicher gelöscht,
  um Datenlecks zu vermeiden.

- **Automatisches Löschen**: Die Anwendung löscht automatisch alle sensiblen
  Daten, wenn über die Dauer von 5 Minuten keine Aktivität festgestellt wird.

- **Durchsatzbegrenzung**: Die Anzahl fehlgeschlagener Entschlüsselungsversuche ist auf 5
  Versuche pro Minute begrenzt, um Brute-Force-Angriffe zu verhindern.

## Funktionen

- Symmetrische Dateiverschlüsselung mit AES-256-GCM
- Passwortbasierte Schlüsselableitung mit Argon2id (OWASP empfohlene Parameter)
- ISO/IEC 7816-4 Padding auf 4 KB Blöcke
- Anforderung von mindestend 15 Zeichen Passwort Länge (NIST 800-63B konform)
- Einfache grafische Benutzeroberfläche, erstellt mit dem Fyne Baukasten
- Funktioneirt auf Linux, macOS, Windows, Android und iOS
- AutoUmschalten zwischen dunklem und hellem Design   

## Kryptografie Übersicht

MicroCrypt verwendet folgende Komponenten:

1. **AES-256-GCM**
  Stellt authentifizierte Verschlüsselung bereit. Dies stellt sowohol Vertraulichkeit als auch Integrität der verschlüsselten Datren sicher. 

2. **Argon2id**
  Eine speicherintensive passwortbasierte Schlüsselableitungsfunktion,
  welche dafür entwickelt wurde um Brute-Force und Grafikkarten-basierte Angriffe abzuwehren.
  Folgende Paramter werden verwendet:
  - Zeit: 3 Durchläufe
  - Speicher: 64 MB
  - Parallelisierung: 4 Threads   

3. **ISO/IEC 7816-4 Padding**
  Die Daten werden vor der Verschlüsselung auf 4-KB-Grenzen aufgefüllt. Dies trägt dazu bei,
  Hinweise auf die ursprüngliche Dateigröße zu minimieren. 

## Verschlüsseltes Ausgabeformat

MicroCrypt erzeugt eine in sich geschlossene, Base64-kodierte Zeichenfolge,
mit folgendem Inhalt:

| Komponente | Länge | Zweck |  
|-----------|--------|---------|  
| Salt | 16 Byte | Verhindert rainbow table Angriffe |   
| Nonce | 12 Byte | Stellt eindeutigen Schiffrentext pro Verschlüsselung sicher |   
| Schiffrentext | Variabel | AES-256-GCM verschlüsselte Daten |  

Die drei Komponenten sind miteinander verkettet und Base64 kodiert, mit Zeilenumbrüchen nach 76 Zeichen, für eine einfachere Handhabung.

## Anwendungsfälle

MicroCrypt finden für folgendes Anwendung:
- Verschlüsselung von provaten Nachrichten oder Notizen mit einem einfachen GUI
- Plattformübergreifende Aufgaben, bei denen das selbe Programm auf verschiedenen Plattformen wie Computer und Smartphone verwendet werden kann
- Benutzer, die eine starke Verschlüsselung einsetzen möchten, ohne dabei eine komplexe Konfiguration vorauszusetzen
- Situationen in denen die Vermeidung von Metadatenlecks wichtig ist

MicroCrypt ist nicht vorgesehen für:
- Die Eingabe umfangreicher/langer Nachrichten oder das Einfügen von Dateien
- Workflows zur Verschlüsselung mit öffentlichen Schlüsseln oder zum Schlüsselaustausch
- Schlüsselverwaltung in Unternehmen oder für mehrere Benutzer
- Automatisierte oder skriptgesteuerte Verschlüsselungspipelines   

Besonderer Dank geht an [Maria Sophia](https://newsgrouper.org/comp.mobile.android/1772049649/1772488033) für das wertvolle Feedback, sowie an [Ffna Sol](https://www.fiverr.com/ffna_sol) für das MicroCrypt Logo. 

![MicroCrypt](img/1.png)
![MicroCrypt](img/2.png)
