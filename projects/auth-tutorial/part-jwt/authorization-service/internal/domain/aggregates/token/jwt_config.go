package token

import "time"

type JWTConfig struct {
	AccessSecret  []byte
	RefreshSecret []byte        // different secret is strongly recommended
	AccessTTL     time.Duration // 5–60 min
	RefreshTTL    time.Duration // 1–14 days
	Issuer        string        // "https://api.yourdomain.com"
}
