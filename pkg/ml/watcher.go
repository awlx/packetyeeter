package ml

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ModelWatcher monitors model files for changes and triggers reloads
type ModelWatcher struct {
	mu            sync.RWMutex
	modelPath     string
	checkInterval time.Duration
	lastChecksum  string
	reloadFunc    func(string) error
	stop          chan struct{}
	wg            sync.WaitGroup
}

// NewModelWatcher creates a new model file watcher
func NewModelWatcher(modelPath string, checkInterval time.Duration, reloadFunc func(string) error) *ModelWatcher {
	return &ModelWatcher{
		modelPath:     modelPath,
		checkInterval: checkInterval,
		reloadFunc:    reloadFunc,
		stop:          make(chan struct{}),
	}
}

// Start begins watching the model file for changes
func (w *ModelWatcher) Start() error {
	// Get initial checksum
	checksum, err := w.getFileChecksum(w.modelPath)
	if err != nil {
		return fmt.Errorf("failed to get initial model checksum: %w", err)
	}
	w.lastChecksum = checksum

	logrus.WithFields(logrus.Fields{
		"model_path":     w.modelPath,
		"check_interval": w.checkInterval,
		"initial_hash":   checksum[:16],
	}).Info("Starting model file watcher")

	w.wg.Add(1)
	go w.watchLoop()

	return nil
}

// Stop stops the watcher
func (w *ModelWatcher) Stop() {
	close(w.stop)
	w.wg.Wait()
}

// watchLoop periodically checks for file changes
func (w *ModelWatcher) watchLoop() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.stop:
			logrus.Info("Model watcher stopped")
			return
		case <-ticker.C:
			if err := w.checkAndReload(); err != nil {
				logrus.WithError(err).Error("Model check/reload failed")
			}
		}
	}
}

// checkAndReload checks if the file has changed and reloads if needed
func (w *ModelWatcher) checkAndReload() error {
	// Get current checksum
	checksum, err := w.getFileChecksum(w.modelPath)
	if err != nil {
		// File might be temporarily unavailable during write
		if os.IsNotExist(err) {
			logrus.WithField("model_path", w.modelPath).Debug("Model file temporarily unavailable")
			return nil
		}
		return fmt.Errorf("failed to get model checksum: %w", err)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Check if file has changed
	if checksum == w.lastChecksum {
		return nil
	}

	logrus.WithFields(logrus.Fields{
		"model_path": w.modelPath,
		"old_hash":   w.lastChecksum[:16],
		"new_hash":   checksum[:16],
	}).Info("🔄 Model file changed - reloading")

	// Reload the model
	if err := w.reloadFunc(w.modelPath); err != nil {
		return fmt.Errorf("failed to reload model: %w", err)
	}

	// Update checksum
	w.lastChecksum = checksum

	logrus.WithField("model_path", w.modelPath).Info("✓ Model reloaded successfully")

	return nil
}

// getFileChecksum calculates the SHA256 checksum of a file
func (w *ModelWatcher) getFileChecksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
