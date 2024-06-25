package utils

import (
	"bytes"
	"encoding/hex"
	"time"

	"github.com/11090815/mayy/protobuf/pcommon"
)

// PeerIdentityType 存储了 peer 节点的证书信息。
type PeerIdentityType []byte

// PKIidType 用于标识 peer 节点的身份标识符。
type PKIidType []byte

func (id PKIidType) String() string {
	if len(id) == 0 {
		return "<nil pki-id>"
	}
	return hex.EncodeToString(id)
}

// IsNotSameFilter 如果给定的另一个 id 与本 id 不一样，则返回 true。
func (id PKIidType) IsNotSameFilter(that PKIidType) bool {
	return !bytes.Equal(id, that)
}

/* ------------------------------------------------------------------------------------------ */

type OrgIdentityType []byte

type PeerIdentityInfo struct {
	PKIid        PKIidType
	Identity     PeerIdentityType
	Organization OrgIdentityType
}

type PeerIdentitySet []PeerIdentityInfo

type MessageCryptoService interface {
	GetPKIidOfCert(identity PeerIdentityType) PKIidType

	VerifyBlock(channelID ChannelID, seqNum uint64, block *pcommon.Block) error

	// VerifyBlockAttestation 与 VerifyBlock 做同样的事情，除了它假设 block.data = nil。因此，它不会计算 block.Data.Hash()
	// 并将其与 block.Header.DataHash 进行比较。当 orderer 交付一个只有 header 和 metadata 的 block 时使用，作为 block 存在的证明。
	VerifyBlockAttestation(channelID ChannelID, block *pcommon.Block) error

	Sign(msg []byte) ([]byte, error)

	Verify(identity PeerIdentityType, signature, message []byte) error

	VerifyByChannel(channelID ChannelID, identity PeerIdentityType, signature, message []byte) error

	ValidateIdentity(identity PeerIdentityType) error

	Expiration(identity PeerIdentityType) (time.Time, error)
}

/* ------------------------------------------------------------------------------------------ */

// SecurityAdvisor 定义了一个提供安全和身份相关功能的外部辅助对象。
type SecurityAdvisor interface {
	// OrgByPeerIdentity 返回对应 peer 节点的组织信息。
	OrgByPeerIdentity(PeerIdentityType) OrgIdentityType
}
