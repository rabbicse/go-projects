package utils

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rabbicse/go-projects/projects/url-shortner/internal/repository"
)

// IDGenerator generates unique IDs using Machine ID + Sequence Number approach
type UniqueIDGenerator struct {
	machineID   string
	sequence    uint64
	sequenceMax uint64
	mu          sync.Mutex
	redisRepo   *repository.RedisRepo
}

// NewIDGenerator creates a new ID generator instance
func NewUniqueIDGenerator(machineID string, sequenceBits uint, redisRepository *repository.RedisRepo) *UniqueIDGenerator {
	// Calculate maximum sequence number based on bits allocated
	maxSeq := uint64(1<<sequenceBits) - 1

	return &UniqueIDGenerator{
		machineID:   machineID,
		sequence:    0,
		sequenceMax: maxSeq,
		redisRepo:   redisRepository,
	}
}

// GenerateID creates a unique short ID
func (g *UniqueIDGenerator) GenerateID() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.sequence >= g.sequenceMax {
		return "", errors.New("sequence number exhausted")
	}

	g.sequence++

	// Format: MachineID + SequenceNumber (padded)
	// Example: "A1" + "0001" = "A10001"
	return fmt.Sprintf("%s%04d", g.machineID, g.sequence), nil
}

// Advanced version with base62 encoding for even shorter URLs
type AdvancedIDGenerator struct {
	machineID uint64
	sequence  uint64
	mu        sync.Mutex
}

func NewAdvancedIDGenerator(machineID uint64) *AdvancedIDGenerator {
	return &AdvancedIDGenerator{
		machineID: machineID,
		sequence:  0,
	}
}

func (g *AdvancedIDGenerator) GenerateShortID() string {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.sequence++

	// Combine machine ID and sequence number into a single number
	combined := (g.machineID << 32) | (g.sequence & 0xFFFFFFFF)

	return Base62Encode(combined)
}

// DistributedIDGenerator for multiple machines
type DistributedIDGenerator struct {
	machineID   uint64
	sequence    uint64
	sequenceMax uint64
	epoch       time.Time
	mu          sync.Mutex
}

func NewDistributedIDGenerator(machineID uint64, sequenceBits uint) *DistributedIDGenerator {
	return &DistributedIDGenerator{
		machineID:   machineID,
		sequence:    0,
		sequenceMax: uint64(1<<sequenceBits) - 1,
		epoch:       time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func (g *DistributedIDGenerator) GenerateSnowflakeLikeID() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()

	timestamp := uint64(time.Since(g.epoch).Milliseconds())

	if g.sequence >= g.sequenceMax {
		// Wait for next millisecond if sequence exhausted
		time.Sleep(time.Millisecond)
		timestamp = uint64(time.Since(g.epoch).Milliseconds())
		g.sequence = 0
	}

	id := (timestamp << 22) | (g.machineID << 12) | g.sequence
	g.sequence++

	return id
}
