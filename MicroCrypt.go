package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"runtime"
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
	// Argon2 parameters following OWASP recommendations
	argon2Time    = 3           // Number of passes/iterations
	argon2Memory  = 64 * 1024   // Memory usage in KB (64 MB)
	argon2Threads = 4           // Degree of parallelism
	argon2KeyLen  = 32          // Output key length in bytes (256 bits)

	// Cryptographic parameters
	saltLen  = 16 // Salt length in bytes (128 bits)
	nonceLen = 12 // Nonce length in bytes for AES-GCM (96 bits)

	// Security and rate limiting
	maxDecryptAttempts = 5                // Maximum failed decryption attempts
	rateLimitDuration  = time.Minute      // Time window for rate limiting
	autoClearDuration  = 60 * time.Second // Auto-clear timeout for inactivity
)

// SecureEntry wraps a Fyne entry widget and stores its content in memguard-protected memory
type SecureEntry struct {
	widget.BaseWidget
	buffer        *memguard.LockedBuffer // Protected memory buffer for sensitive text
	placeholder   string                 // Placeholder text when buffer is empty
	mu            sync.Mutex             // Mutex for thread-safe access
	onChanged     func()                 // Callback triggered when content changes
	internalEntry *widget.Entry          // Reference to the underlying Fyne entry widget
	lastActivity  time.Time              // Timestamp of last user activity (for auto-clear)
}

// NewSecureEntry creates and initializes a new SecureEntry widget
func NewSecureEntry() *SecureEntry {
	se := &SecureEntry{
		placeholder:  "Enter text...",
		lastActivity: time.Now(),
	}
	se.ExtendBaseWidget(se)
	return se
}

// SetText securely stores the provided text in a memguard-protected buffer
func (se *SecureEntry) SetText(text string) {
	se.mu.Lock()

	// Securely destroy any existing buffer before replacing it
	if se.buffer != nil {
		se.buffer.Destroy()
	}

	// Allocate new protected buffer if text is non-empty
	if text != "" {
		se.buffer = memguard.NewBufferFromBytes([]byte(text))
	} else {
		se.buffer = nil
	}

	se.lastActivity = time.Now()
	se.mu.Unlock()

	se.Refresh()

	// Trigger change callback if registered
	if se.onChanged != nil {
		se.onChanged()
	}
}

// GetText returns the current content as a plain string (use with caution)
// Caller is responsible for handling the returned string securely
func (se *SecureEntry) GetText() string {
	se.mu.Lock()
	defer se.mu.Unlock()

	if se.buffer == nil {
		return ""
	}
	return string(se.buffer.Bytes())
}

// GetBuffer returns direct access to the protected buffer for secure operations
func (se *SecureEntry) GetBuffer() *memguard.LockedBuffer {
	se.mu.Lock()
	defer se.mu.Unlock()
	return se.buffer
}

// Clear securely wipes and deallocates the protected buffer
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

// SetPlaceHolder sets the placeholder text displayed when the entry is empty
func (se *SecureEntry) SetPlaceHolder(text string) {
	se.mu.Lock()
	se.placeholder = text
	se.mu.Unlock()
	se.Refresh()
}

// SetOnChanged registers a callback function to be invoked on content changes
func (se *SecureEntry) SetOnChanged(callback func()) {
	se.mu.Lock()
	se.onChanged = callback
	se.mu.Unlock()
}

// SelectAll selects all text in the internal entry widget
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

// CreateRenderer implements the fyne.Widget interface for custom rendering
func (se *SecureEntry) CreateRenderer() fyne.WidgetRenderer {
	// Initialize the internal multi-line entry widget
	internalEntry := widget.NewMultiLineEntry()
	internalEntry.SetPlaceHolder(se.placeholder)
	internalEntry.Wrapping = fyne.TextWrapWord
	internalEntry.TextStyle = fyne.TextStyle{Monospace: true}

	// Store reference for later access
	se.mu.Lock()
	se.internalEntry = internalEntry
	se.mu.Unlock()

	// Sync initial content from secure buffer to display widget
	se.mu.Lock()
	if se.buffer != nil {
		internalEntry.Text = string(se.buffer.Bytes())
	}
	se.mu.Unlock()

	// Bind real-time user input to secure buffer updates
	internalEntry.OnChanged = func(newText string) {
		var callback func()

		se.mu.Lock()
		se.lastActivity = time.Now()

		// Securely replace the old buffer
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

	// Sync internal entry if content has changed
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
	textArea *SecureEntry // Main text input/output area

	passphrase *memguard.LockedBuffer // Protected storage for current passphrase
	secureText *memguard.LockedBuffer // Protected storage for processed text

	isDarkTheme bool  // Current theme state
	isMobile    bool  // Device type flag for responsive layout

	mu sync.RWMutex // Mutex for thread-safe state access

	// Audit and rate-limiting fields
	decryptAttempts int
	lastAttempt     time.Time
	lastOperation   string
	operationTime   time.Time
}

// main initializes the application and starts the UI event loop
func main() {
	// Ensure all sensitive memory is purged on exit
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

	// Set initial window size based on device type
	if editor.isMobile {
		editor.window.Resize(fyne.NewSize(360, 640))
	} else {
		editor.window.Resize(fyne.NewSize(400, 640))
	}

	// Start background auto-clear task for security audit compliance
	go func() {
		for {
			time.Sleep(5 * time.Second)
			if editor.textArea != nil {
				editor.textArea.mu.Lock()
				if editor.textArea.buffer != nil && time.Since(editor.textArea.lastActivity) > autoClearDuration {
					editor.textArea.mu.Unlock()
					editor.clearEditor()
					// Use fyne.Do to ensure dialog runs on main UI thread
					fyne.Do(func() {
						dialog.ShowInformation("", "Sensitive data auto-cleared\ndue to inactivity", editor.window)
					})
				} else {
					editor.textArea.mu.Unlock()
				}
			}
		}
	}()

	// Intercept window close to perform secure cleanup
	editor.window.SetCloseIntercept(func() {
		editor.cleanup()
		editor.window.Close()
	})

	editor.window.ShowAndRun()
}

// setupMobileUI constructs the responsive user interface layout
func (e *SecureEditor) setupMobileUI() fyne.CanvasObject {
	e.textArea = NewSecureEntry()
	e.textArea.SetPlaceHolder("Enter text...")

	// Primary action buttons
	encryptBtn := widget.NewButton("Encrypt", e.encryptText)
	encryptBtn.Importance = widget.HighImportance
	decryptBtn := widget.NewButton("Decrypt", e.decryptText)
	decryptBtn.Importance = widget.HighImportance
	clearBtn := widget.NewButton("Clear", e.clearEditor)
	clearBtn.Importance = widget.MediumImportance

	// Secondary utility buttons
	selectAllBtn := widget.NewButton("Select All", e.selectAll)
	selectAllBtn.Importance = widget.MediumImportance
	copyBtn := widget.NewButton("Copy", e.copyToClipboard)
	copyBtn.Importance = widget.MediumImportance
	pasteBtn := widget.NewButton("Paste", e.pasteFromClipboard)
	pasteBtn.Importance = widget.MediumImportance

	// Theme toggle button
	themeSwitch := widget.NewButtonWithIcon("", theme.ViewRefreshIcon(), e.toggleTheme)
	themeSwitch.Importance = widget.LowImportance

	topBar := container.NewHBox(layout.NewSpacer(), themeSwitch)

	// Responsive layout based on screen size
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

// isVerySmallScreen checks if the window width is below the mobile threshold
func (e *SecureEditor) isVerySmallScreen() bool {
	size := e.window.Canvas().Size()
	return size.Width > 0 && size.Width < 360
}

// selectAll triggers text selection in the secure text area
func (e *SecureEditor) selectAll() {
	if e.textArea != nil {
		e.textArea.SelectAll()
	}
}

// copyToClipboard copies the current text to the system clipboard with auto-clear
func (e *SecureEditor) copyToClipboard() {
	e.mu.RLock()
	text := e.textArea.GetText()
	e.mu.RUnlock()

	if text == "" {
		dialog.ShowInformation("", "Nothing to copy", e.window)
		return
	}

	// Convert line endings for Windows compatibility
	e.window.Clipboard().SetContent(strings.ReplaceAll(text, "\n", "\r\n"))

	// Auto-clear clipboard after delay for security
	go func() {
		time.Sleep(15 * time.Second)
		if e.window != nil {
			e.window.Clipboard().SetContent("")
		}
	}()
}

// pasteFromClipboard appends clipboard content to the secure text area
func (e *SecureEditor) pasteFromClipboard() {
	e.mu.Lock()
	defer e.mu.Unlock()

	text := e.window.Clipboard().Content()
	if text == "" {
		dialog.ShowInformation("", "Clipboard is empty", e.window)
		return
	}

	// Normalize line endings
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	e.textArea.SetText(e.textArea.GetText() + text)
}

// toggleTheme switches between dark and light UI themes
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
	e.window.Content().Refresh()
}

func (e *SecureEditor) askPassword(callback func(*memguard.LockedBuffer, error)) {
    passEntry := widget.NewPasswordEntry()
    passEntry.SetPlaceHolder("")
    formItems := []*widget.FormItem{widget.NewFormItem("Password", passEntry)}

    dlg := dialog.NewForm("", "OK", "Cancel", formItems, func(confirmed bool) {
        if !confirmed {
            callback(nil, errors.New("cancelled"))
            return
        }
        if len(passEntry.Text) < 12 {
            dialog.ShowInformation("", "Password too short\nMinimum 12 characters required", e.window)
            return
        }
        result := memguard.NewBufferFromBytes([]byte(passEntry.Text))
        passEntry.Text = ""
        passEntry.Refresh()
        callback(result, nil)
    }, e.window)

    if fyne.CurrentDevice().IsMobile() {
        dlg.Resize(fyne.NewSize(320, 140))
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

// formatBase64Short formats base64 output with line breaks for readability
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

// decodeFormattedBase64 removes whitespace and decodes formatted base64 input
func decodeFormattedBase64(data string) ([]byte, error) {
	cleanData := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, data)
	return base64.StdEncoding.DecodeString(cleanData)
}

// cleanup securely destroys all sensitive data in memory
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
	if e.window != nil {
		e.window.Clipboard().SetContent("")
	}
	runtime.GC()
}

// clearEditor securely wipes the text area and associated buffers
func (e *SecureEditor) clearEditor() {
	if e.textArea.GetText() == "" {
		dialog.ShowInformation("", "Text area is already empty", e.window)
		return
	}
	e.cleanup()
}

// encryptText handles the encryption workflow with input validation
func (e *SecureEditor) encryptText() {
	e.mu.RLock()
	text := e.textArea.GetText()
	e.mu.RUnlock()

	// Validate input and show user feedback if empty
	if text == "" {
		dialog.ShowInformation("", "Please enter text to encrypt", e.window)
		return
	}

	e.askPassword(func(passphrase *memguard.LockedBuffer, err error) {
		if err != nil {
			return
		}
		defer passphrase.Destroy()

		encryptedData, err := e.performEncryption([]byte(text), passphrase)
		if err != nil {
			dialog.ShowError(err, e.window)
			return
		}

		e.mu.Lock()
		e.textArea.SetText(encryptedData)
		e.mu.Unlock()
	})
}

// performEncryption executes the AES-GCM encryption with Argon2 key derivation
func (e *SecureEditor) performEncryption(textBytes []byte, passphrase *memguard.LockedBuffer) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.lastOperation = "encrypt"
	e.operationTime = time.Now()

	// Apply padding to obscure plaintext length
	paddedText := padTo1024Multiple(textBytes)
	textBuffer := memguard.NewBufferFromBytes(paddedText)
	defer textBuffer.Destroy()

	// Generate random salt and nonce for this encryption operation
	salt, nonce := make([]byte, saltLen), make([]byte, nonceLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	// Derive encryption key using Argon2id
	key := argon2.IDKey(passphrase.Bytes(), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// Perform AES-GCM encryption
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ciphertext := aesgcm.Seal(nil, nonce, textBuffer.Bytes(), nil)

	// Concatenate salt + nonce + ciphertext for storage
	encryptedData := append(salt, append(nonce, ciphertext...)...)
	return formatBase64Short(base64.StdEncoding.EncodeToString(encryptedData)), nil
}

// decryptText handles the decryption workflow with input validation and rate limiting
func (e *SecureEditor) decryptText() {
	e.mu.RLock()
	text := e.textArea.GetText()
	e.mu.RUnlock()

	// Validate input and show user feedback if empty
	if text == "" {
		dialog.ShowInformation("", "Please paste encrypted text to decrypt", e.window)
		return
	}

	e.askPassword(func(passphrase *memguard.LockedBuffer, err error) {
		if err != nil {
			return
		}
		defer passphrase.Destroy()

		decryptedText, err := e.performDecryption(text, passphrase)
		if err != nil {
			dialog.ShowError(err, e.window)
			return
		}

		e.mu.Lock()
		e.textArea.SetText(decryptedText)
		e.mu.Unlock()
	})
}

// performDecryption executes the AES-GCM decryption with Argon2 key derivation
func (e *SecureEditor) performDecryption(encryptedData string, passphrase *memguard.LockedBuffer) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.lastOperation = "decrypt"
	e.operationTime = time.Now()

	// Rate limiting: prevent brute-force attacks
	now := time.Now()
	if now.Sub(e.lastAttempt) > rateLimitDuration {
		e.decryptAttempts = 0
	}
	e.lastAttempt = now

	if e.decryptAttempts >= maxDecryptAttempts {
		return "", errors.New("rate limited: too many failed attempts")
	}
	e.decryptAttempts++

	// Decode and parse the encrypted payload
	encryptedBytes, err := decodeFormattedBase64(encryptedData)
	if err != nil || len(encryptedBytes) < saltLen+nonceLen {
		return "", errors.New("invalid encrypted data format")
	}

	salt := encryptedBytes[:saltLen]
	nonce := encryptedBytes[saltLen : saltLen+nonceLen]
	ciphertext := encryptedBytes[saltLen+nonceLen:]

	// Derive decryption key using the same Argon2 parameters
	key := argon2.IDKey(passphrase.Bytes(), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// Perform AES-GCM decryption and authentication
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
		return "", errors.New("authentication failed: incorrect password or corrupted data")
	}

	// Reset attempt counter on successful decryption
	e.decryptAttempts = 0

	// Remove padding and return plaintext
	plaintextBuffer := memguard.NewBufferFromBytes(plaintext)
	defer plaintextBuffer.Destroy()

	cleanText, err := remove1024Padding(plaintextBuffer.Bytes())
	if err != nil {
		return "", err
	}
	return string(cleanText), nil
}

// padTo1024Multiple adds minimal padding to align data to 1024-byte boundaries
func padTo1024Multiple(data []byte) []byte {
	const blockSize = 1024
	paddingNeeded := blockSize - (len(data) % blockSize)
	if paddingNeeded == blockSize {
		paddingNeeded = 0
	}
	if paddingNeeded == 0 {
		return data
	}
	paddedData := make([]byte, len(data)+paddingNeeded)
	copy(paddedData, data)
	// Mark padding start with 0x80 byte
	paddedData[len(data)] = 0x80
	return paddedData
}

// remove1024Padding strips padding added by padTo1024Multiple
func remove1024Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("cannot remove padding from empty data")
	}
	// Search backwards for padding marker
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == 0x80 {
			return data[:i], nil
		}
	}
	// No padding marker found: return data as-is (may be unpadded)
	return data, nil
}
