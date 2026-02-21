package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

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

// SecureEditor structure for the editor
type SecureEditor struct {
	app         fyne.App
	window      fyne.Window
	textArea    *widget.Entry
	passphrase  *memguard.LockedBuffer
	secureText  *memguard.LockedBuffer
	isDarkTheme bool
}

func main() {
	// Initialize MemGuard and ensure secure cleanup
	memguard.CatchInterrupt()
	defer memguard.Purge()

	// Create Fyne app
	myApp := app.NewWithID("oc2mx.net.microcrypt")
	editor := &SecureEditor{
		app:         myApp,
		isDarkTheme: true,
	}

	editor.window = myApp.NewWindow("MicroCrypt")
	
	// Set initial theme
	myApp.Settings().SetTheme(theme.DarkTheme())

	// Create responsive UI
	content := editor.setupResponsiveUI()
	editor.window.SetContent(content)
	
	// Window settings
	editor.window.SetPadded(true)
	editor.window.SetMaster()
	
	// Larger window for better text area usage
	editor.window.Resize(fyne.NewSize(600, 600))
	
	editor.window.SetCloseIntercept(func() {
		editor.cleanup()
		editor.window.Close()
	})
	
	editor.window.ShowAndRun()
}

// setupResponsiveUI creates a responsive layout without status bar
func (e *SecureEditor) setupResponsiveUI() fyne.CanvasObject {
	// Create text area
	e.textArea = widget.NewMultiLineEntry()
	e.textArea.SetPlaceHolder("Enter text...")
	e.textArea.Wrapping = fyne.TextWrapWord
	e.textArea.TextStyle = fyne.TextStyle{Monospace: true}
	
	// Monitor text changes
	e.textArea.OnChanged = e.onTextChanged

	// Create buttons
	encryptBtn := widget.NewButton("Encrypt", e.encryptText)
	encryptBtn.Importance = widget.MediumImportance
	
	decryptBtn := widget.NewButton("Decrypt", e.decryptText)
	decryptBtn.Importance = widget.MediumImportance
	
	clearBtn := widget.NewButton("Clear", e.clearEditor)
	clearBtn.Importance = widget.MediumImportance

	// Theme switch button
	themeSwitch := widget.NewButtonWithIcon("", theme.ViewRefreshIcon(), e.toggleTheme)
	themeSwitch.Importance = widget.LowImportance

	// Top bar with theme switch
	topBar := container.NewHBox(
		layout.NewSpacer(),
		themeSwitch,
	)

	// Button row - centered with spacing
	buttonRow := container.NewHBox(
		layout.NewSpacer(),
		encryptBtn,
		widget.NewLabel("    "),
		decryptBtn,
		widget.NewLabel("    "),
		clearBtn,
		layout.NewSpacer(),
	)

	// Header container (no status bar at bottom)
	headerContainer := container.NewVBox(
		topBar,
		widget.NewSeparator(),
		container.NewPadded(buttonRow),
		widget.NewSeparator(),
	)

	// Main layout: header top, textarea fills the rest
	mainContent := container.NewBorder(
		headerContainer, // Top only
		nil,             // No bottom
		nil,             // No left
		nil,             // No right
		e.textArea,      // Center fills everything
	)

	return container.NewPadded(mainContent)
}

// padTo1024Multiple adds padding to make data a multiple of 1024 bytes
func padTo4096Multiple(data []byte) []byte {
	const blockSize = 1024
	dataLen := len(data)
	
	paddingNeeded := blockSize - (dataLen % blockSize)
	if paddingNeeded == blockSize {
		paddingNeeded = 0
	}
	
	if paddingNeeded == 0 {
		return data
	}
	
	paddedData := make([]byte, dataLen+paddingNeeded)
	copy(paddedData, data)
	paddedData[dataLen] = 0x80 // Padding marker (ISO/IEC 7816-4)
	
	return paddedData
}

// remove1024Padding removes padding from 1024-byte blocks
func remove1024Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	
	// Search for padding marker from the end
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == 0x80 {
			// Verify that all bytes after marker are zero
			for j := i + 1; j < len(data); j++ {
				if data[j] != 0x00 {
					return nil, errors.New("invalid padding: non-zero after marker")
				}
			}
			return data[:i], nil
		}
	}
	
	// No padding marker found - return unpadded data
	return data, nil
}

// copyToClipboard copies text to clipboard with CRLF line endings
func (e *SecureEditor) copyToClipboard() {
	text := e.textArea.Text
	if text != "" {
		text = strings.ReplaceAll(text, "\n", "\r\n")
		e.window.Clipboard().SetContent(text)
	}
}

// toggleTheme switches between dark and light theme
func (e *SecureEditor) toggleTheme() {
	if e.isDarkTheme {
		e.app.Settings().SetTheme(theme.LightTheme())
		e.isDarkTheme = false
	} else {
		e.app.Settings().SetTheme(theme.DarkTheme())
		e.isDarkTheme = true
	}
	e.window.Content().Refresh()
}

// formatBase64Short formats base64 with 24 characters per line for small smartphone and messenger screens
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

// decodeFormattedBase64 removes line breaks before decoding
func decodeFormattedBase64(data string) ([]byte, error) {
	cleanData := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, data)
	return base64.StdEncoding.DecodeString(cleanData)
}

// onTextChanged is called on every text change
func (e *SecureEditor) onTextChanged(newText string) {
	// Securely delete old protected text
	if e.secureText != nil {
		e.secureText.Destroy()
	}
	// Store new text in protected memory
	if newText != "" {
		e.secureText = memguard.NewBufferFromBytes([]byte(newText))
	}
	// Auto-copy to clipboard
	e.copyToClipboard()
}

// cleanup securely terminates and clears memory
func (e *SecureEditor) cleanup() {
	if e.passphrase != nil {
		e.passphrase.Destroy()
		e.passphrase = nil
	}
	if e.secureText != nil {
		e.secureText.Destroy()
		e.secureText = nil
	}
	e.textArea.SetText("")
}

// clearEditor deletes sensitive data and clears clipboard
func (e *SecureEditor) clearEditor() {
	e.cleanup()
	e.window.Clipboard().SetContent("")
	dialog.ShowInformation("", "All data cleared", e.window)
}

// askPassword shows a password entry dialog
func (e *SecureEditor) askPassword(callback func(*memguard.LockedBuffer, error)) {
	password := widget.NewPasswordEntry()

	formItems := []*widget.FormItem{
		widget.NewFormItem("Password", password),
	}

	dlg := dialog.NewForm(
		"",
		"OK",
		"Cancel",
		formItems,
		func(confirmed bool) {
			if !confirmed {
				callback(nil, errors.New("cancelled"))
				return
			}
			if len(password.Text) < 12 {
				callback(nil, errors.New("password too short = <12"))
				return
			}
			result := memguard.NewBufferFromBytes([]byte(password.Text))
			callback(result, nil)
		},
		e.window,
	)

	dlg.Resize(fyne.NewSize(400, 150))
	dlg.Show()
}

// encryptText encrypts the text and displays it
func (e *SecureEditor) encryptText() {
	text := e.textArea.Text
	if text == "" {
		dialog.ShowInformation("", "No text to encrypt", e.window)
		return
	}

	e.askPassword(func(passphrase *memguard.LockedBuffer, err error) {
		if err != nil {
			if err.Error() != "cancelled" {
				dialog.ShowError(err, e.window)
			}
			return
		}
		defer passphrase.Destroy()

		encryptedData, err := e.performEncryption([]byte(text), passphrase)
		if err != nil {
			dialog.ShowError(fmt.Errorf("encryption failed: %v", err), e.window)
			return
		}

		e.textArea.SetText(encryptedData)
	})
}

// performEncryption performs the actual encryption with 4096-byte padding
func (e *SecureEditor) performEncryption(textBytes []byte, passphrase *memguard.LockedBuffer) (string, error) {
	// Pad to 4096-byte multiple
	paddedText := padTo4096Multiple(textBytes)
	textBuffer := memguard.NewBufferFromBytes(paddedText)
	defer textBuffer.Destroy()

	// Generate salt and nonce
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt error: %v", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce error: %v", err)
	}

	// Derive key with Argon2id
	key := argon2.IDKey(passphrase.Bytes(), salt, 3, 64*1024, 4, 32)

	// Prepare AES-GCM encryption
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("cipher error: %v", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM error: %v", err)
	}

	// Encrypt text
	ciphertext := aesgcm.Seal(nil, nonce, textBuffer.Bytes(), nil)

	// Combine data: salt + nonce + ciphertext
	encryptedData := make([]byte, 0, 16+12+len(ciphertext))
	encryptedData = append(encryptedData, salt...)
	encryptedData = append(encryptedData, nonce...)
	encryptedData = append(encryptedData, ciphertext...)

	// Return base64-encoded data with 32-char line breaks
	base64Data := base64.StdEncoding.EncodeToString(encryptedData)
	return formatBase64Short(base64Data), nil
}

// decryptText decrypts text from the text area
func (e *SecureEditor) decryptText() {
	text := e.textArea.Text
	if text == "" {
		dialog.ShowInformation("", "No text to decrypt", e.window)
		return
	}

	e.askPassword(func(passphrase *memguard.LockedBuffer, err error) {
		if err != nil {
			if err.Error() != "cancelled" {
				dialog.ShowError(err, e.window)
			}
			return
		}
		defer passphrase.Destroy()

		decryptedText, err := e.performDecryption(text, passphrase)
		if err != nil {
			dialog.ShowError(fmt.Errorf("decryption failed"), e.window)
			return
		}

		e.textArea.SetText(decryptedText)
	})
}

// performDecryption performs the actual decryption and removes 4096-byte padding
func (e *SecureEditor) performDecryption(encryptedData string, passphrase *memguard.LockedBuffer) (string, error) {
	// Decode base64 data
	encryptedBytes, err := decodeFormattedBase64(encryptedData)
	if err != nil {
		return "", fmt.Errorf("decode error: %v", err)
	}
	if len(encryptedBytes) < 28 {
		return "", fmt.Errorf("data too short")
	}

	salt := encryptedBytes[:16]
	nonce := encryptedBytes[16:28]
	ciphertext := encryptedBytes[28:]

	// Derive key
	key := argon2.IDKey(passphrase.Bytes(), salt, 3, 64*1024, 4, 32)

	// Prepare AES-GCM decryption
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("cipher error: %v", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM error: %v", err)
	}

	// Decrypt text
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("wrong password")
	}

	// Remove 4096-byte padding
	cleanText, err := remove1024Padding(plaintext)
	if err != nil {
		return "", fmt.Errorf("padding error: %v", err)
	}

	return string(cleanText), nil
}
