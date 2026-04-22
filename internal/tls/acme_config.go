package tls

type AcmeConfig struct {
	Enabled       bool
	Email         string
	CAServer      string
	ChallengeType string // "http", "tls-alpn"
}
