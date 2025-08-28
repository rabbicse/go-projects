package utils

import (
	"crypto/md5"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/rabbicse/go-projects/projects/url-shortner/internal/repository"
)

// IDGenerator generates unique IDs using Machine ID + Sequence Number approach
type UniqueIDGenerator struct {
	datacenterID int64
	machineID    int64
	sequence     int64
	sequenceMax  int64
	mu           sync.Mutex
	redisRepo    *repository.RedisRepo
}

// NewIDGenerator creates a new ID generator instance
func NewUniqueIDGenerator(machineID int64, sequenceBits int64, redisRepository *repository.RedisRepo) *UniqueIDGenerator {
	// Calculate maximum sequence number based on bits allocated
	maxSeq := int64(1<<sequenceBits) - 1

	return &UniqueIDGenerator{
		machineID:   machineID,
		sequence:    0,
		sequenceMax: maxSeq,
		redisRepo:   redisRepository,
	}
}

// GenerateID creates a unique short ID
// Snowflake like id:
// 1 bit = 0
// 41 bits = timestamp
// 5 bits = datacenter ID
// 5 bits = machine ID
// 12 bits = sequence numer
// Since 5 bits = 11111 in binary (which is 31 decimal), you can bitwise AND with 0x1F:
func (g *UniqueIDGenerator) GenerateSnowflakeID() (string, error) {
	// mutex lock to handle concurrency
	g.mu.Lock()
	defer g.mu.Unlock()

	datacenterID := g.datacenterID & 0x1F // keep 5 bits (0-31)

	machineID := g.machineID & 0x1F // keep 5 bits (0-31)

	// Get current timestamp in milliseconds
	timestamp := time.Now().UnixMilli()

	// Use Redis cluster to generate sequence number
	seq, err := g.redisRepo.GetNextSequence("url:shortener")
	if err != nil {
		return "", fmt.Errorf("failed to generate sequence: %v", err)
	}

	if g.sequence >= g.sequenceMax {
		return "", errors.New("sequence number exhausted")
	}

	// 4. Combine into 64-bit integer:
	// sign (0) | 41 bits timestamp | 5 bits datacenter | 5 bits machine | 12 bits sequence
	id := packSnowflakeBits(timestamp, datacenterID, machineID, seq)

	log.Printf("Unique id after pack: %v\n", id)

	return Base62Encode(id), nil
}

// GenerateID creates a unique short ID
// Snowflake like id:
// 5 bits = datacenter ID
// 5 bits = machine ID
// 12 bits = sequence numer
// Since 5 bits = 11111 in binary (which is 31 decimal), you can bitwise AND with 0x1F:
func (g *UniqueIDGenerator) GenerateID() (string, error) {
	// mutex lock to handle concurrency
	g.mu.Lock()
	defer g.mu.Unlock()

	datacenterID := g.datacenterID & 0x1F // keep 5 bits (0-31)

	machineID := g.machineID & 0x1F // keep 5 bits (0-31)

	// Use Redis cluster to generate sequence number
	seq, err := g.redisRepo.GetNextSequence("url:shortener")
	if err != nil {
		return "", fmt.Errorf("failed to generate sequence: %v", err)
	}

	if g.sequence >= g.sequenceMax {
		return "", errors.New("sequence number exhausted")
	}

	// 4. Combine into 64-bit integer:
	// sign (0) | 41 bits timestamp | 5 bits datacenter | 5 bits machine | 12 bits sequence
	// id := packBits(datacenterID, machineID, seq)
	id := GenerateMD5Hash(datacenterID, machineID, seq)

	log.Printf("Unique id after pack: %v\n", id)

	return Base62EncodeBytes(id), nil
}

func packSnowflakeBits(timestamp int64, datacenterID int64, machineID int64, seq int64) int64 {
	seq &= 0xFFF // 12 bits
	return (timestamp << 22) | (datacenterID << 17) | (machineID << 12) | seq
}

func packBits(datacenterID int64, machineID int64, seq int64) int64 {
	seq &= 0xFFF // 12 bits
	return (datacenterID << 17) | (machineID << 12) | seq
}

func GenerateMD5Hash(dcID, machineID, seq int64) []byte {
	input := fmt.Sprintf("%d:%d:%d", dcID, machineID, seq)
	hash := md5.Sum([]byte(input))
	return hash[:] // 16 bytes
}
