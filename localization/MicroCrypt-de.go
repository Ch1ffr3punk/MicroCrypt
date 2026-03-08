package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
)

const (
	// Argon2-Parameter gemäß OWASP-Empfehlungen
	argon2Time    = 3           // Anzahl der Iterationen
	argon2Memory  = 64 * 1024   // Speichernutzung in KB (64 MB)
	argon2Threads = 4           // Parallelisierungsgrad
	argon2KeyLen  = 32          // Ausgabeschlüssellänge in Bytes (256 Bits)

	// Kryptografische Parameter
	saltLen  = 16 // Salt-Länge in Bytes (128 Bits)
	nonceLen = 12 // Nonce-Länge für AES-GCM in Bytes (96 Bits)

	// Sicherheit und Ratenbegrenzung
	maxDecryptAttempts = 5                // Maximale fehlgeschlagene Entschlüsselungsversuche
	rateLimitDuration  = time.Minute      // Zeitfenster für Ratenbegrenzung
	autoClearDuration  = 5 * time.Minute  // Auto-Lösch-Timeout bei Inaktivität
)

// SecureEntry kapselt ein Fyne-Eingabefeld und speichert den Inhalt in memguard-geschütztem Speicher
type SecureEntry struct {
	widget.BaseWidget
	buffer        *memguard.LockedBuffer // Geschützter Speicher für sensitiven Text
	placeholder   string                 // Platzhaltertext wenn Puffer leer ist
	mu            sync.Mutex             // Mutex für thread-sicheren Zugriff
	onChanged     func()                 // Callback bei Inhaltsänderung
	internalEntry *widget.Entry          // Referenz zum zugrundeliegenden Fyne-Eingabefeld
	lastActivity  time.Time              // Zeitstempel der letzten Benutzeraktivität (für Auto-Löschung)
}

// NewSecureEntry erstellt und initialisiert ein neues SecureEntry-Widget
func NewSecureEntry() *SecureEntry {
	se := &SecureEntry{
		placeholder:  "Text eingeben...",
		lastActivity: time.Now(),
	}
	se.ExtendBaseWidget(se)
	return se
}

// SetText speichert den übergebenen Text sicher in einem memguard-geschützten Puffer
func (se *SecureEntry) SetText(text string) {
	se.mu.Lock()

	// Vorhandenen Puffer sicher löschen bevor er ersetzt wird
	if se.buffer != nil {
		se.buffer.Destroy()
	}

	// Neuen geschützten Puffer allozieren wenn Text nicht leer ist
	if text != "" {
		se.buffer = memguard.NewBufferFromBytes([]byte(text))
	} else {
		se.buffer = nil
	}

	se.lastActivity = time.Now()
	se.mu.Unlock()

	se.Refresh()

	// Änderungs-Callback auslösen falls registriert
	if se.onChanged != nil {
		se.onChanged()
	}
}

// GetText gibt den aktuellen Inhalt als einfachen String zurück.
// SICHERHEITSWARNUNG: Der zurückgegebene String befindet sich im normalen Heap-Speicher
// und ist NICHT durch memguard geschützt. Er kann im Speicher verbleiben bis der GC läuft.
// Nur für kurzlebige Operationen verwenden (z.B. Zwischenablage kopieren) und Ergebnis nicht speichern.
func (se *SecureEntry) GetText() string {
	se.mu.Lock()
	defer se.mu.Unlock()

	if se.buffer == nil {
		return ""
	}
	return string(se.buffer.Bytes())
}

// WithBuffer führt die übergebene Funktion mit direktem Zugriff auf den geschützten Puffer aus.
// Dies vermeidet die Erstellung ungeschützter String-Kopien und ist die bevorzugte Methode zur Verarbeitung sensibler Daten.

func (se *SecureEntry) WithBuffer(fn func(*memguard.LockedBuffer) error) error {
	se.mu.Lock()
	defer se.mu.Unlock()

	if se.buffer == nil {
		return errors.New("Puffer ist leer")
	}
	return fn(se.buffer)
}

// GetBuffer gibt direkten Zugriff auf den geschützten Puffer für sichere Operationen.
// Wenn möglich WithBuffer() verwenden, um versehentliche Offenlegung zu vermeiden.
func (se *SecureEntry) GetBuffer() *memguard.LockedBuffer {
	se.mu.Lock()
	defer se.mu.Unlock()
	return se.buffer
}

// Clear löscht und dealloziert den geschützten Puffer sicher
func (se *SecureEntry) Clear() {
	se.mu.Lock()

	if se.buffer != nil {
		se.buffer.Destroy()
		se.buffer = nil
	}

	se.mu.Unlock()
	se.Refresh()

	if se.onChanged != nil {
		se.onChanged()
	}
}

// SetPlaceHolder setzt den Platzhaltertext, der angezeigt wird wenn das Feld leer ist
func (se *SecureEntry) SetPlaceHolder(text string) {
	se.mu.Lock()
	se.placeholder = text
	se.mu.Unlock()
	se.Refresh()
}

// SetOnChanged registriert eine Callback-Funktion für Inhaltsänderungen
func (se *SecureEntry) SetOnChanged(callback func()) {
	se.mu.Lock()
	se.onChanged = callback
	se.mu.Unlock()
}

// SelectAll wählt den gesamten Text im internen Eingabefeld aus
func (se *SecureEntry) SelectAll() {
	se.mu.Lock()
	internal := se.internalEntry
	se.mu.Unlock()

	if internal != nil {
		if canvas := fyne.CurrentApp().Driver().CanvasForObject(se); canvas != nil {
			canvas.Focus(internal)
		}
		internal.TypedShortcut(&fyne.ShortcutSelectAll{})
	}
}

// CreateRenderer implementiert das fyne.Widget-Interface für benutzerdefinierte Darstellung
func (se *SecureEntry) CreateRenderer() fyne.WidgetRenderer {
	// Internes mehrzeiliges Eingabefeld initialisieren
	internalEntry := widget.NewMultiLineEntry()
	internalEntry.SetPlaceHolder(se.placeholder)
	internalEntry.Wrapping = fyne.TextWrapWord
	internalEntry.TextStyle = fyne.TextStyle{Monospace: true}

	// Referenz für späteren Zugriff speichern
	se.mu.Lock()
	se.internalEntry = internalEntry
	se.mu.Unlock()

	// Initialen Inhalt vom sicheren Puffer in Anzeigefeld synchronisieren
	se.mu.Lock()
	if se.buffer != nil {
		internalEntry.Text = string(se.buffer.Bytes())
	}
	se.mu.Unlock()

	// Echtzeit-Benutzereingaben an sicheren Puffer binden
	internalEntry.OnChanged = func(newText string) {
		var callback func()

		se.mu.Lock()
		se.lastActivity = time.Now()

		// Alten Puffer sicher ersetzen
		if se.buffer != nil {
			se.buffer.Destroy()
		}

		if newText != "" {
			se.buffer = memguard.NewBufferFromBytes([]byte(newText))
		} else {
			se.buffer = nil
		}

		callback = se.onChanged
		se.mu.Unlock()

		if callback != nil {
			callback()
		}
	}

	return &secureEntryRenderer{
		secureEntry:   se,
		internalEntry: internalEntry,
	}
}

type secureEntryRenderer struct {
	secureEntry   *SecureEntry
	internalEntry *widget.Entry
}

func (r *secureEntryRenderer) Layout(size fyne.Size) {
	r.internalEntry.Resize(size)
}

func (r *secureEntryRenderer) MinSize() fyne.Size {
	return r.internalEntry.MinSize()
}

func (r *secureEntryRenderer) Refresh() {
	r.secureEntry.mu.Lock()
	var bufferText string
	if r.secureEntry.buffer != nil {
		bufferText = string(r.secureEntry.buffer.Bytes())
	}
	placeholder := r.secureEntry.placeholder
	r.secureEntry.mu.Unlock()

	// Internes Eingabefeld synchronisieren wenn Inhalt geändert
	if bufferText != r.internalEntry.Text {
		r.internalEntry.SetText(bufferText)
	}
	if placeholder != r.internalEntry.PlaceHolder {
		r.internalEntry.PlaceHolder = placeholder
	}
	r.internalEntry.Refresh()
}

func (r *secureEntryRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.internalEntry}
}

func (r *secureEntryRenderer) Destroy() {}

func (se *SecureEntry) FocusGained() { se.Refresh() }
func (se *SecureEntry) FocusLost()   { se.Refresh() }
func (se *SecureEntry) TypedRune(r rune) {
	if se.internalEntry != nil {
		se.internalEntry.TypedRune(r)
	}
}
func (se *SecureEntry) TypedKey(key *fyne.KeyEvent) {
	if se.internalEntry != nil {
		se.internalEntry.TypedKey(key)
	}
}
func (se *SecureEntry) AcceptsTab() bool { return false }

// SecureEditor repräsentiert die Hauptanwendungsstruktur für den sicheren Texteditor
type SecureEditor struct {
	app      fyne.App
	window   fyne.Window
	textArea *SecureEntry // Haupttext-Eingabe-/Ausgabebereich

	passphrase *memguard.LockedBuffer // Geschützter Speicher für aktuelle Passphrase
	secureText *memguard.LockedBuffer // Geschützter Speicher für verarbeiteten Text

	isDarkTheme bool // Aktueller Theme-Status
	isMobile    bool // Gerätetyp-Flag für responsives Layout

	mu sync.RWMutex // Mutex für thread-sicheren Zustandszugriff

	// Audit- und Ratenbegrenzungs-Felder
	decryptAttempts int
	lastAttempt     time.Time
	lastOperation   string
	operationTime   time.Time

	// Referenz zum Theme-Umschaltknopf für dynamische Icon-Updates
	themeSwitch *widget.Button
}

// main initialisiert die Anwendung und startet die UI-Ereignisschleife
func main() {
	// Sicherstellen dass aller sensibler Speicher beim Beenden gelöscht wird
	defer memguard.Purge()
	memguard.CatchInterrupt()

	myApp := app.NewWithID("oc2mx.net.microcrypt")
	editor := &SecureEditor{
		app:         myApp,
		isDarkTheme: true,
		isMobile:    fyne.CurrentDevice().IsMobile(),
	}

	editor.window = myApp.NewWindow("MicroCrypt")
	myApp.Settings().SetTheme(theme.DarkTheme())

	content := editor.setupMobileUI()
	editor.window.SetContent(content)
	editor.window.SetPadded(false)
	editor.window.SetMaster()

	// Anfangsgröße des Fensters basierend auf Gerätetyp festlegen
	if editor.isMobile {
		editor.window.Resize(fyne.NewSize(360, 640))
	} else {
		editor.window.Resize(fyne.NewSize(400, 640))
	}

	// Hintergrundaufgabe für automatische Löschung starten (Sicherheitsaudit-Konformität)
	go func() {
		for {
			time.Sleep(5 * time.Second)
			if editor.textArea != nil {
				editor.textArea.mu.Lock()
				if editor.textArea.buffer != nil && time.Since(editor.textArea.lastActivity) > autoClearDuration {
					editor.textArea.mu.Unlock()
					editor.clearEditor()
					// fyne.Do verwenden um sicherzustellen dass Dialog im Haupt-UI-Thread läuft
					fyne.Do(func() {
						dialog.ShowInformation("", "Sensible Daten aufgrund von\nInaktivität automatisch gelöscht", editor.window)
					})
				} else {
					editor.textArea.mu.Unlock()
				}
			}
		}
	}()

	// Fensterschließen abfangen um sichere Bereinigung durchzuführen
	editor.window.SetCloseIntercept(func() {
		editor.cleanup()
		editor.window.Close()
	})

	editor.window.ShowAndRun()
}

// getThemeIcon gibt das passende Emoji für den aktuellen Theme-Status zurück
func (e *SecureEditor) getThemeIcon() string {
	if e.isDarkTheme {
		return "☀️"
	}
	return "🌙"
}

// setupMobileUI erstellt das responsive Benutzeroberflächen-Layout
func (e *SecureEditor) setupMobileUI() fyne.CanvasObject {
	e.textArea = NewSecureEntry()
	e.textArea.SetPlaceHolder("Text eingeben...")

	// Primäre Aktionsschaltflächen
	encryptBtn := widget.NewButton("Verschlüsseln", e.encryptText)
	encryptBtn.Importance = widget.HighImportance
	decryptBtn := widget.NewButton("Entschlüsseln", e.decryptText)
	decryptBtn.Importance = widget.HighImportance
	clearBtn := widget.NewButton("Löschen", e.clearEditor)
	clearBtn.Importance = widget.MediumImportance

	// Sekundäre Hilfsschaltflächen
	selectAllBtn := widget.NewButton("Alles auswählen", e.selectAll)
	selectAllBtn.Importance = widget.MediumImportance
	copyBtn := widget.NewButton("Kopieren", e.copyToClipboard)
	copyBtn.Importance = widget.MediumImportance
	pasteBtn := widget.NewButton("Einfügen", e.pasteFromClipboard)
	pasteBtn.Importance = widget.MediumImportance

	// Theme-Umschaltknopf mit Emoji-Icon (Android-kompatibel)
	e.themeSwitch = widget.NewButton(e.getThemeIcon(), e.toggleTheme)
	e.themeSwitch.Importance = widget.LowImportance

	topBar := container.NewHBox(layout.NewSpacer(), e.themeSwitch)

	// Responsives Layout basierend auf Bildschirmgröße
	var firstButtonRow fyne.CanvasObject
	var secondButtonRow fyne.CanvasObject

	if e.isVerySmallScreen() {
		firstButtonRow = container.NewVBox(encryptBtn, decryptBtn, clearBtn)
		secondButtonRow = container.NewVBox(selectAllBtn, copyBtn, pasteBtn)
	} else if e.isMobile {
		firstButtonRow = container.New(layout.NewGridLayoutWithColumns(3),
			encryptBtn, decryptBtn, clearBtn)
		secondButtonRow = container.New(layout.NewGridLayoutWithColumns(3),
			selectAllBtn, copyBtn, pasteBtn)
	} else {
		firstButtonRow = container.New(layout.NewGridLayoutWithColumns(3),
			encryptBtn, decryptBtn, clearBtn)
		secondButtonRow = container.New(layout.NewGridLayoutWithColumns(3),
			selectAllBtn, copyBtn, pasteBtn)
	}

	headerContainer := container.NewVBox(
		topBar,
		widget.NewSeparator(),
		container.NewPadded(firstButtonRow),
		container.NewPadded(secondButtonRow),
		widget.NewSeparator(),
	)

	return container.NewPadded(
		container.NewBorder(headerContainer, nil, nil, nil, container.NewVScroll(e.textArea)),
	)
}

// isVerySmallScreen prüft ob die Fensterbreite unterhalb der mobilen Schwelle liegt
func (e *SecureEditor) isVerySmallScreen() bool {
	width := e.window.Canvas().Size().Width
	return width > 0 && width < 360
}

// selectAll löst die Textauswahl im sicheren Textbereich aus
func (e *SecureEditor) selectAll() {
	if e.textArea != nil {
		e.textArea.SelectAll()
	}
}

// copyToClipboard kopiert den aktuellen Text in die System-Zwischenablage mit Sicherheitswarnung und Auto-Löschung
func (e *SecureEditor) copyToClipboard() {
	e.mu.RLock()
	text := e.textArea.GetText()
	e.mu.RUnlock()

	if text == "" {
		dialog.ShowInformation("", "Nichts zu kopieren", e.window)
		return
	}

	// Zeilenumbrüche für Windows-Kompatibilität konvertieren
	e.window.Clipboard().SetContent(strings.ReplaceAll(text, "\n", "\r\n"))

	// Zwischenablage nach Verzögerung aus Sicherheitsgründen automatisch löschen
	go func() {
		time.Sleep(15 * time.Second)
		if e.window != nil && e.window.Clipboard() != nil {
			e.window.Clipboard().SetContent("")
		}
	}()
}

// pasteFromClipboard fügt Inhalt der Zwischenablage an den sicheren Textbereich an
func (e *SecureEditor) pasteFromClipboard() {
	e.mu.Lock()
	defer e.mu.Unlock()

	text := e.window.Clipboard().Content()
	if text == "" {
		dialog.ShowInformation("", "Zwischenablage ist leer", e.window)
		return
	}

	// Zeilenumbrüche normalisieren
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	e.textArea.SetText(e.textArea.GetText() + text)
}

// toggleTheme wechselt zwischen dunklem und hellem UI-Theme
func (e *SecureEditor) toggleTheme() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.isDarkTheme {
		e.app.Settings().SetTheme(theme.LightTheme())
		e.isDarkTheme = false
	} else {
		e.app.Settings().SetTheme(theme.DarkTheme())
		e.isDarkTheme = true
	}

	// Theme-Knopf-Icon aktualisieren um neuen Zustand widerzuspiegeln und UI aktualisieren
	if e.themeSwitch != nil {
		e.themeSwitch.SetText(e.getThemeIcon())
		e.themeSwitch.Refresh()
	}
	e.window.Content().Refresh()
}

// askPassword fordert den Benutzer zur Eingabe eines Passworts mit Mindestlängen-Validierung auf
func (e *SecureEditor) askPassword(callback func(*memguard.LockedBuffer, error)) {
	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("")
	formItems := []*widget.FormItem{widget.NewFormItem("Passwort", passEntry)}

	dlg := dialog.NewForm("", "OK", "Abbrechen", formItems, func(confirmed bool) {
		if !confirmed {
			callback(nil, errors.New("abgebrochen"))
			return
		}
		if len(passEntry.Text) < 15 {
			dialog.ShowInformation("", "Passwort zu kurz\nMindestens 15 Zeichen erforderlich", e.window)
			return
		}
		result := memguard.NewBufferFromBytes([]byte(passEntry.Text))
		passEntry.Text = ""
		passEntry.Refresh()
		callback(result, nil)
	}, e.window)

	if fyne.CurrentDevice().IsMobile() {
		dlg.Resize(fyne.NewSize(320, 100))
	} else {
		dlg.Resize(fyne.NewSize(350, 180))
	}

	dlg.Show()

	// Passwortfeld fokussieren nachdem Dialog gerendert wurde
	time.AfterFunc(50*time.Millisecond, func() {
		fyne.Do(func() {
			e.window.Canvas().Focus(passEntry)
		})
	})
}

// formatBase64Short formatiert Base64-Ausgabe mit Zeilenumbrüchen für bessere Lesbarkeit
func formatBase64Short(data string) string {
	const lineLength = 24
	var result strings.Builder
	for i := 0; i < len(data); i += lineLength {
		end := i + lineLength
		if end > len(data) {
			end = len(data)
		}
		result.WriteString(data[i:end])
		if end < len(data) {
			result.WriteString("\n")
		}
	}
	return result.String()
}

// decodeFormattedBase64 entfernt Leerzeichen und dekodiert formatierte Base64-Eingabe
func decodeFormattedBase64(data string) ([]byte, error) {
	cleanData := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, data)
	return base64.StdEncoding.DecodeString(cleanData)
}

// cleanup zerstört sicher alle sensiblen Daten im Speicher.
// Hinweis: Go's GC kann Kopien sensibler Daten im Heap bis zur Sammlung behalten.
// memguard schützt unsere LockedBuffers; für Strings/[]byte verlassen wir uns auf Nullsetzung
// und hoffen dass der GC sie schnell einsammelt. Perfekte Speicherhygiene ist in purem Go
// ohne unsichere Operationen nicht möglich.
func (e *SecureEditor) cleanup() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.passphrase != nil {
		e.passphrase.Destroy()
		e.passphrase = nil
	}
	if e.secureText != nil {
		e.secureText.Destroy()
		e.secureText = nil
	}
	if e.textArea != nil {
		e.textArea.Clear()
	}
	if e.window != nil && e.window.Clipboard() != nil {
		e.window.Clipboard().SetContent("")
	}
	// runtime.GC() absichtlich weggelassen: keine Garantie für sofortige Ausführung,
	// und memguard verwaltet bereits sichere Speicherbereiche.
}

// clearEditor löscht sicher den Textbereich und zugehörige Puffer
func (e *SecureEditor) clearEditor() {
	if e.textArea.GetText() == "" {
		dialog.ShowInformation("", "Textbereich ist bereits leer", e.window)
		return
	}
	e.cleanup()
}

// encryptText behandelt den Verschlüsselungsablauf mit Eingabevalidierung.
// Verwendet eine asynchrone Passwortabfrage und stellt Thread-Sicherheit durch
// Sperren des Editor-Status nur zu Beginn des Verschlüsselungsprozesses sicher.
func (e *SecureEditor) encryptText() {
	// 1. Erste Prüfung des UI-Status (Read-Lock)
	e.mu.RLock()
	if e.textArea == nil {
		e.mu.RUnlock()
		return
	}
	text := e.textArea.GetText()
	e.mu.RUnlock()

	// Eingabe vor Passwortabfrage validieren
	if text == "" {
		dialog.ShowInformation("", "Bitte Text zum Verschlüsseln eingeben", e.window)
		return
	}

	// 2. Passwort vom Benutzer anfordern (Asynchroner UI-Dialog)
	e.askPassword(func(passphrase *memguard.LockedBuffer, err error) {
		if err != nil {
			// Benutzer abgebrochen oder Validierung fehlgeschlagen
			return
		}
		// Sicherstellen dass der sensible Passwort-Puffer nach diesem Callback zerstört wird
		defer passphrase.Destroy()

		// 3. Verschlüsselung durchführen (Write-Lock)
		// Hier sperren um die Operationsmetadaten und den internen Zustand zu schützen
		e.mu.Lock()
		
		// Operationsverfolgung für Audit/Zwecke aktualisieren
		e.lastOperation = "encrypt"
		e.operationTime = time.Now()

		// Kryptografische Logik ausführen
		// Hilfsfunktion verwenden um Verschlüsselungslogik sauber zu halten
		encryptedData, encErr := e.internalEncrypt([]byte(text), passphrase)
		
		if encErr != nil {
			e.mu.Unlock()
			dialog.ShowError(encErr, e.window)
			return
		}

		// UI mit Ergebnis aktualisieren und Sperre freigeben
		e.textArea.SetText(encryptedData)
		e.mu.Unlock()
		
	})
}

// internalEncrypt enthält die kernkryptografische Logik für AES-GCM.
// Geht davon aus dass der Aufrufer die Mutex-Sperre behandelt.
func (e *SecureEditor) internalEncrypt(textBytes []byte, passphrase *memguard.LockedBuffer) (string, error) {
	// Padding anwenden um Klartextlänge zu verschleiern (Verkehrsanalyse-Resistenz)
	paddedText := padTo1024Multiple(textBytes)
	textBuffer := memguard.NewBufferFromBytes(paddedText)
	defer textBuffer.Destroy()

	// Zufälliges Salt und Nonce generieren
	salt, nonce := make([]byte, saltLen), make([]byte, nonceLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	// Verschlüsselungsschlüssel mit Argon2id ableiten
	key := argon2.IDKey(passphrase.Bytes(), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	// Schlüssel sicher nullen nachdem Block-Chiffre initialisiert wurde
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// AES-GCM initialisieren
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Gepaddete Daten verschlüsseln
	ciphertext := aesgcm.Seal(nil, nonce, textBuffer.Bytes(), nil)

	// Komponenten kombinieren: Salt + Nonce + Ciphertext
	combinedPayload := append(salt, append(nonce, ciphertext...)...)
	
	// Als formatiertes Base64 für einfaches Kopieren/Einfügen zurückgeben
	return formatBase64Short(base64.StdEncoding.EncodeToString(combinedPayload)), nil
}

// decryptText behandelt den Entschlüsselungsablauf mit Eingabevalidierung und Ratenbegrenzung.
// Verwendet einen asynchronen Callback für die Passworteingabe und stellt Thread-Sicherheit
// durch Sperren der Mutex nur bei Beginn der tatsächlichen Verarbeitung sicher.
func (e *SecureEditor) decryptText() {
	// 1. Erste Prüfung des UI-Status (Read-Lock)
	e.mu.RLock()
	if e.textArea == nil {
		e.mu.RUnlock()
		return
	}
	text := e.textArea.GetText()
	e.mu.RUnlock()

	// Eingabe vor Passwortabfrage validieren
	if text == "" {
		dialog.ShowInformation("", "Bitte verschlüsselten Text\nzum Entschlüsseln einfügen", e.window)
		return
	}

	// 2. Passwort vom Benutzer anfordern (Asynchroner UI-Dialog)
	e.askPassword(func(passphrase *memguard.LockedBuffer, err error) {
		if err != nil {
			// Benutzer abgebrochen oder Passwort zu kurz
			return
		}
		// Sicherstellen dass der sensible Passwort-Puffer nach diesem Callback zerstört wird
		defer passphrase.Destroy()

		// 3. Sensitive Operationen beginnen (Write-Lock)
		// Hier sperren weil wir den Ratenbegrenzungs-Status ändern/lesen
		// und die kryptografischen Operationen durchführen.
		e.mu.Lock()
		
		// Operationsverfolgung aktualisieren
		e.lastOperation = "decrypt"
		e.operationTime = time.Now()

		// Ratenbegrenzung: prüfen ob Benutzer aktuell blockiert ist
		now := time.Now()
		if now.Sub(e.lastAttempt) > rateLimitDuration {
			e.decryptAttempts = 0
		}
		e.lastAttempt = now

		if e.decryptAttempts >= maxDecryptAttempts {
			e.mu.Unlock() // Vor Dialog-Anzeige entsperren um UI-Deadlocks zu vermeiden
			dialog.ShowError(errors.New("Ratenbegrenzung: zu viele fehlgeschlagene Versuche"), e.window)
			return
		}

		// Tatsächliche Entschlüsselung durchführen
        // Hinweis: Die Logik „performDecryption“ wird hierher verschoben/integriert oder unter der Voraussetzung aufgerufen, 
        // dass die Sperre bereits gesetzt ist.
		decryptedText, decErr := e.internalDecrypt(text, passphrase)
		
		if decErr != nil {
			e.decryptAttempts++
			e.mu.Unlock()
			dialog.ShowError(decErr, e.window)
			return
		}

		// Erfolg: Versuche zurücksetzen und UI aktualisieren
		e.decryptAttempts = 0
		e.textArea.SetText(decryptedText)
		e.mu.Unlock()
		
	})
}

// internalDecrypt führt die kryptografischen Kernoperationen durch.
// Geht davon aus dass der Aufrufer die Mutex-Sperre für den gemeinsamen Zustand behandelt.
func (e *SecureEditor) internalDecrypt(encryptedData string, passphrase *memguard.LockedBuffer) (string, error) {
	// Verschlüsselte Nutzlast dekodieren und parsen
	encryptedBytes, err := decodeFormattedBase64(encryptedData)
	if err != nil || len(encryptedBytes) < saltLen+nonceLen {
		return "", errors.New("ungültiges Format der verschlüsselten Daten")
	}

	salt := encryptedBytes[:saltLen]
	nonce := encryptedBytes[saltLen : saltLen+nonceLen]
	ciphertext := encryptedBytes[saltLen+nonceLen:]

	// Entschlüsselungsschlüssel mit Argon2id ableiten
	// passphrase.Bytes() direkt aus geschütztem Speicher verwenden
	key := argon2.IDKey(passphrase.Bytes(), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	defer func() {
		// Manuelles Nullen des abgeleiteten Schlüssels für zusätzliche Sicherheit
		for i := range key {
			key[i] = 0
		}
	}()

	// AES-GCM initialisieren
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Entschlüsseln und Authentifizierungs-Tag verifizieren
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("Authentifizierung fehlgeschlagen: falsches Passwort oder korrupte Daten")
	}

	// Sicherheits-Padding entfernen (Verkehrsanalyse-Resistenz)
	plaintextBuffer := memguard.NewBufferFromBytes(plaintext)
	defer plaintextBuffer.Destroy()

	cleanText, err := remove1024Padding(plaintextBuffer.Bytes())
	if err != nil {
		return "", err
	}
	
	return string(cleanText), nil
}

// padTo1024Multiple fügt minimales Padding hinzu um Klartextlängenmuster zu verschleiern.
// Verwendet ISO/IEC 7816-4 Stil-Padding: 0x80-Marker gefolgt von Nullbytes.
// Dies ist NICHT für kryptografisches Padding (AES-GCM benötigt keins) sondern für
// Verkehrsanalyse-Resistenz durch Ausrichtung der Ausgabe an festen Grenzen.
func padTo1024Multiple(data []byte) []byte {
	const blockSize = 1024
	remainder := len(data) % blockSize

	// Bereits ausgerichtet → kein Padding nötig
	if remainder == 0 {
		return data
	}

	paddingNeeded := blockSize - remainder
	paddedData := make([]byte, len(data)+paddingNeeded)
	copy(paddedData, data)

	// ISO/IEC 7816-4 Padding-Marker
	paddedData[len(data)] = 0x80
	// Verbleibende Bytes bleiben 0x00 (durch make null-initialisiert)

	return paddedData
}

// remove1024Padding entfernt Padding das von padTo1024Multiple hinzugefügt wurde.
// Gibt Fehler zurück wenn Padding-Marker fehlt oder beschädigt ist.
func remove1024Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("Padding kann nicht von leeren Daten entfernt werden")
	}

	// Daten bereits ausgerichtet? Prüfen ob Padding tatsächlich vorhanden ist
	if len(data)%1024 != 0 {
		// Nicht ausgerichtet → wahrscheinlich ungepaddet, wie erhalten zurückgeben
		return data, nil
	}

	// Rückwärts nach dem 0x80-Marker suchen
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == 0x80 {
			return data[:i], nil
		}
		// Wenn wir auf Nicht-Null-Bytes stoßen bevor wir 0x80 finden, könnten Daten beschädigt sein
		// oder legitimerweise Binärdaten enthalten. Konservativer Ansatz: wie erhalten zurückgeben.
		if data[i] != 0x00 {
			break
		}
	}

	// Kein Marker gefunden → annehmen dass Daten ohne Padding gespeichert wurden
	return data, nil
}
