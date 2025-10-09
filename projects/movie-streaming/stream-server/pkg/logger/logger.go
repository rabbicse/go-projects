package logger

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Init initializes the logger
func Init(level string) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// Set log level
	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		logLevel = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(logLevel)

	// Configure logger output
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}

// Info returns an info level logger
func Info() *zerolog.Event {
	return log.Info()
}

// Error returns an error level logger
func Error() *zerolog.Event {
	return log.Error()
}

// Debug returns a debug level logger
func Debug() *zerolog.Event {
	return log.Debug()
}

// Warn returns a warn level logger
func Warn() *zerolog.Event {
	return log.Warn()
}
