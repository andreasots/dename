package protocol

const (
	SIGN_TAG_TRANSFER = (1 << 8) + iota
	SIGN_TAG_COMMIT
	SIGN_TAG_ACK
	SIGN_TAG_PUBLISH
)
