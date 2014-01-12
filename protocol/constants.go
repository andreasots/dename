package protocol

import "github.com/andres-erbsen/dename/consensus"

const (
	SIGN_TAG_TRANSFER = (1 << 8) + iota
	SIGN_TAG_COMMIT
	SIGN_TAG_ACK
	SIGN_TAG_PUBLISH
)

var ConsensusSignTags = map[int]uint64{
	consensus.COMMITMENT:      SIGN_TAG_COMMIT,
	consensus.ACKNOWLEDGEMENT: SIGN_TAG_ACK,
	consensus.PUBLISH:         SIGN_TAG_PUBLISH,
}
