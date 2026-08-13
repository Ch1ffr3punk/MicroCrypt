package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/url"
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
	argon2Time    = 3
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32

	saltLen  = 16
	nonceLen = 12

	maxDecryptAttempts = 5
	rateLimitDuration  = time.Minute
	autoClearDuration  = 5 * time.Minute

	padBlockSize = 4096
)

type SecureEntry struct {
	widget.BaseWidget
	buffer        *memguard.LockedBuffer
	placeholder   string
	mu            sync.Mutex
	onChanged     func()
	internalEntry *widget.Entry
	lastActivity  time.Time
}

func NewSecureEntry() *SecureEntry {
	se := &SecureEntry{
		placeholder:  "Inserisci il testo...",
		lastActivity: time.Now(),
	}
	se.ExtendBaseWidget(se)
	return se
}

func (se *SecureEntry) SetText(text string) {
	se.mu.Lock()

	if se.buffer != nil {
		se.buffer.Destroy()
	}

	if text != "" {
		se.buffer = memguard.NewBufferFromBytes([]byte(text))
	} else {
		se.buffer = nil
	}

	se.lastActivity = time.Now()
	se.mu.Unlock()

	se.Refresh()

	if se.onChanged != nil {
		se.onChanged()
	}
}

func (se *SecureEntry) GetText() string {
	se.mu.Lock()
	defer se.mu.Unlock()

	if se.buffer == nil {
		return ""
	}
	return string(se.buffer.Bytes())
}

func (se *SecureEntry) WithBuffer(fn func(*memguard.LockedBuffer) error) error {
	se.mu.Lock()
	defer se.mu.Unlock()

	if se.buffer == nil {
		return errors.New("buffer non inizializzato")
	}
	return fn(se.buffer)
}

func (se *SecureEntry) GetBuffer() *memguard.LockedBuffer {
	se.mu.Lock()
	defer se.mu.Unlock()
	return se.buffer
}

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

func (se *SecureEntry) SetPlaceHolder(text string) {
	se.mu.Lock()
	se.placeholder = text
	se.mu.Unlock()
	se.Refresh()
}

func (se *SecureEntry) SetOnChanged(callback func()) {
	se.mu.Lock()
	se.onChanged = callback
	se.mu.Unlock()
}

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

func (se *SecureEntry) CreateRenderer() fyne.WidgetRenderer {
	internalEntry := widget.NewMultiLineEntry()
	internalEntry.SetPlaceHolder(se.placeholder)
	internalEntry.Wrapping = fyne.TextWrapOff
	internalEntry.TextStyle = fyne.TextStyle{Monospace: true}

	se.mu.Lock()
	se.internalEntry = internalEntry
	se.mu.Unlock()

	se.mu.Lock()
	if se.buffer != nil {
		internalEntry.Text = string(se.buffer.Bytes())
	}
	se.mu.Unlock()

	internalEntry.OnChanged = func(newText string) {
		var callback func()

		se.mu.Lock()
		se.lastActivity = time.Now()

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

type SecureEditor struct {
	app      fyne.App
	window   fyne.Window
	textArea *SecureEntry

	passphrase *memguard.LockedBuffer
	secureText *memguard.LockedBuffer

	isDarkTheme bool
	isMobile    bool

	mu sync.RWMutex

	decryptAttempts int
	lastAttempt     time.Time
	lastOperation   string
	operationTime   time.Time

	themeSwitch *widget.Button
}

func main() {
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

	if editor.isMobile {
		editor.window.Resize(fyne.NewSize(360, 640))
	} else {
		editor.window.Resize(fyne.NewSize(720, 720))
		editor.window.CenterOnScreen()
	}

	go func() {
		for {
			time.Sleep(5 * time.Second)
			if editor.textArea != nil {
				editor.textArea.mu.Lock()
				if editor.textArea.buffer != nil && time.Since(editor.textArea.lastActivity) > autoClearDuration {
					editor.textArea.mu.Unlock()
					editor.clearEditor()
					fyne.Do(func() {
						dialog.ShowInformation("", "Dati sensibili eliminati automaticamente\nper inattività", editor.window)
					})
				} else {
					editor.textArea.mu.Unlock()
				}
			}
		}
	}()

	editor.window.SetCloseIntercept(func() {
		editor.cleanup()
		editor.window.Close()
	})

	editor.window.ShowAndRun()
}

func (e *SecureEditor) getThemeIcon() string {
	if e.isDarkTheme {
		return "☀️"
	}
	return "🌙"
}

func (e *SecureEditor) showInfoPopup() {
	projURL, _ := url.Parse("https://github.com/Ch1ffr3punk/MicroCrypt")

	projectLink := widget.NewHyperlink("Un progetto open source", projURL)

	okButton := widget.NewButton("OK", func() {
		overlays := e.window.Canvas().Overlays()
		if overlays.Top() != nil {
			overlays.Remove(overlays.Top())
		}
	})
	okButton.Importance = widget.HighImportance

	content := container.NewVBox(
		widget.NewLabelWithStyle("MicroCrypt v0.1.3", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		container.NewHBox(
			layout.NewSpacer(),
			projectLink,
			layout.NewSpacer(),
		),
		widget.NewLabelWithStyle("distribuito con licenza Apache 2.0", fyne.TextAlignCenter, fyne.TextStyle{}),
		widget.NewLabelWithStyle("© 2026 Ch1ffr3punk", fyne.TextAlignCenter, fyne.TextStyle{}),
		container.NewHBox(
			layout.NewSpacer(),
			okButton,
			layout.NewSpacer(),
		),
	)

	dialog.ShowCustomWithoutButtons("", content, e.window)
}

func (e *SecureEditor) setupMobileUI() fyne.CanvasObject {
	e.textArea = NewSecureEntry()
	e.textArea.SetPlaceHolder("Inserisci il testo...")

	encryptBtn := widget.NewButton("Cifra", e.encryptText)
	encryptBtn.Importance = widget.HighImportance
	decryptBtn := widget.NewButton("Decifra", e.decryptText)
	decryptBtn.Importance = widget.HighImportance
	clearBtn := widget.NewButton("Svuota", e.clearEditor)
	clearBtn.Importance = widget.MediumImportance

	selectAllBtn := widget.NewButton("Seleziona tutto", e.selectAll)
	selectAllBtn.Importance = widget.MediumImportance
	copyBtn := widget.NewButton("Copia", e.copyToClipboard)
	copyBtn.Importance = widget.MediumImportance
	pasteBtn := widget.NewButton("Incolla", e.pasteFromClipboard)
	pasteBtn.Importance = widget.MediumImportance

	infoBtn := widget.NewButtonWithIcon("", theme.InfoIcon(), e.showInfoPopup)
	infoBtn.Importance = widget.LowImportance

	e.themeSwitch = widget.NewButton(e.getThemeIcon(), e.toggleTheme)
	e.themeSwitch.Importance = widget.LowImportance

	topBar := container.NewHBox(
		infoBtn,
		layout.NewSpacer(),
		e.themeSwitch,
	)

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

	textScroll := container.NewScroll(e.textArea)

	return container.NewPadded(
		container.NewBorder(headerContainer, nil, nil, nil, textScroll),
	)
}

func (e *SecureEditor) isVerySmallScreen() bool {
	width := e.window.Canvas().Size().Width
	return width > 0 && width < 360
}

func (e *SecureEditor) selectAll() {
	if e.textArea != nil {
		e.textArea.SelectAll()
	}
}

func (e *SecureEditor) copyToClipboard() {
	e.mu.RLock()
	text := e.textArea.GetText()
	e.mu.RUnlock()

	if text == "" {
		dialog.ShowInformation("", "Nessun testo da copiare", e.window)
		return
	}

	e.window.Clipboard().SetContent(strings.ReplaceAll(text, "\n", "\r\n"))

	go func() {
		time.Sleep(15 * time.Second)
		if e.window != nil && e.window.Clipboard() != nil {
			e.window.Clipboard().SetContent("")
		}
	}()
}

func (e *SecureEditor) pasteFromClipboard() {
	e.mu.Lock()
	defer e.mu.Unlock()

	text := e.window.Clipboard().Content()
	if text == "" {
		dialog.ShowInformation("", "Gli appunti sono vuoti", e.window)
		return
	}

	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	e.textArea.SetText(e.textArea.GetText() + text)
}

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

	if e.themeSwitch != nil {
		e.themeSwitch.SetText(e.getThemeIcon())
		e.themeSwitch.Refresh()
	}
	e.window.Content().Refresh()
}

func (e *SecureEditor) askPassword(callback func(*memguard.LockedBuffer, error)) {
	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("")
	formItems := []*widget.FormItem{widget.NewFormItem("Password", passEntry)}

	dlg := dialog.NewForm("", "OK", "Annulla", formItems, func(confirmed bool) {
		if !confirmed {
			callback(nil, errors.New("operazione annullata"))
			return
		}
		if len(passEntry.Text) < 15 {
			dialog.ShowInformation("", "Password troppo corta\nSono richiesti almeno 15 caratteri", e.window)
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

	time.AfterFunc(50*time.Millisecond, func() {
		fyne.Do(func() {
			e.window.Canvas().Focus(passEntry)
		})
	})
}

func formatBase64Short(data string) string {
	const lineLength = 76
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

func decodeFormattedBase64(data string) ([]byte, error) {
	cleanData := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, data)
	return base64.StdEncoding.DecodeString(cleanData)
}

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
}

func (e *SecureEditor) clearEditor() {
	if e.textArea.GetText() == "" {
		dialog.ShowInformation("", "L’area di testo è già vuota", e.window)
		return
	}
	e.cleanup()
}

func (e *SecureEditor) encryptText() {
	e.mu.RLock()
	if e.textArea == nil {
		e.mu.RUnlock()
		return
	}
	text := e.textArea.GetText()
	e.mu.RUnlock()

	if text == "" {
		dialog.ShowInformation("", "Inserisci il testo da cifrare", e.window)
		return
	}

	e.askPassword(func(passphrase *memguard.LockedBuffer, err error) {
		if err != nil {
			return
		}
		defer passphrase.Destroy()

		e.mu.Lock()

		e.lastOperation = "encrypt"
		e.operationTime = time.Now()

		encryptedData, encErr := e.internalEncrypt([]byte(text), passphrase)

		if encErr != nil {
			e.mu.Unlock()
			dialog.ShowError(encErr, e.window)
			return
		}

		e.textArea.SetText(encryptedData)
		e.mu.Unlock()
	})
}

func (e *SecureEditor) internalEncrypt(textBytes []byte, passphrase *memguard.LockedBuffer) (string, error) {
	paddedText := padTo4096Multiple(textBytes)
	textBuffer := memguard.NewBufferFromBytes(paddedText)
	defer textBuffer.Destroy()

	salt, nonce := make([]byte, saltLen), make([]byte, nonceLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	key := argon2.IDKey(passphrase.Bytes(), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesgcm.Seal(nil, nonce, textBuffer.Bytes(), nil)

	combinedPayload := append(salt, append(nonce, ciphertext...)...)

	return formatBase64Short(base64.StdEncoding.EncodeToString(combinedPayload)), nil
}

func (e *SecureEditor) decryptText() {
	e.mu.RLock()
	if e.textArea == nil {
		e.mu.RUnlock()
		return
	}
	text := e.textArea.GetText()
	e.mu.RUnlock()

	if text == "" {
		dialog.ShowInformation("", "Incolla il testo cifrato da decifrare", e.window)
		return
	}

	e.askPassword(func(passphrase *memguard.LockedBuffer, err error) {
		if err != nil {
			return
		}
		defer passphrase.Destroy()

		e.mu.Lock()

		e.lastOperation = "decrypt"
		e.operationTime = time.Now()

		now := time.Now()
		if now.Sub(e.lastAttempt) > rateLimitDuration {
			e.decryptAttempts = 0
		}
		e.lastAttempt = now

		if e.decryptAttempts >= maxDecryptAttempts {
			e.mu.Unlock()
			dialog.ShowError(errors.New("troppi tentativi falliti: riprova più tardi"), e.window)
			return
		}

		decryptedText, decErr := e.internalDecrypt(text, passphrase)

		if decErr != nil {
			e.decryptAttempts++
			e.mu.Unlock()
			dialog.ShowError(decErr, e.window)
			return
		}

		e.decryptAttempts = 0
		e.textArea.SetText(decryptedText)
		e.mu.Unlock()
	})
}

func (e *SecureEditor) internalDecrypt(encryptedData string, passphrase *memguard.LockedBuffer) (string, error) {
	encryptedBytes, err := decodeFormattedBase64(encryptedData)
	if err != nil || len(encryptedBytes) < saltLen+nonceLen {
		return "", errors.New("formato dei dati cifrati non valido")
	}

	salt := encryptedBytes[:saltLen]
	nonce := encryptedBytes[saltLen : saltLen+nonceLen]
	ciphertext := encryptedBytes[saltLen+nonceLen:]

	key := argon2.IDKey(passphrase.Bytes(), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("autenticazione fallita: password errata o dati danneggiati")
	}

	plaintextBuffer := memguard.NewBufferFromBytes(plaintext)
	defer plaintextBuffer.Destroy()

	cleanText, err := remove4096Padding(plaintextBuffer.Bytes())
	if err != nil {
		return "", err
	}

	return string(cleanText), nil
}

func padTo4096Multiple(data []byte) []byte {
	remainder := len(data) % padBlockSize

	if remainder == 0 {
		return data
	}

	paddingNeeded := padBlockSize - remainder
	paddedData := make([]byte, len(data)+paddingNeeded)
	copy(paddedData, data)

	paddedData[len(data)] = 0x80

	return paddedData
}

func remove4096Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("impossibile rimuovere il padding da dati vuoti")
	}

	if len(data)%padBlockSize != 0 {
		return data, nil
	}

	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == 0x80 {
			return data[:i], nil
		}
		if data[i] != 0x00 {
			break
		}
	}

	return data, nil
}
