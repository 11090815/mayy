package msp

type MSPVersion int

const (
	MSPv1_0 MSPVersion = iota
)

/* ------------------------------------------------------------------------------------------ */

type ProviderType int

const (
	CSP ProviderType = iota
	OTHER
)

var mspTypeStrings = map[ProviderType]string{
	CSP:   "csp",
	OTHER: "other",
}

func ProviderTypeToString(id ProviderType) string {
	if res, found := mspTypeStrings[id]; found {
		return res
	}
	return mspTypeStrings[OTHER]
}

var Options = map[string]NewOpts{
	ProviderTypeToString(CSP): &CSPNewOpts{Version: MSPv1_0},
}

/* ------------------------------------------------------------------------------------------ */

// IdentityIdentifier 表示身份标识，由 msp_id 和自己的身份 id 组成。
type IdentityIdentifier struct {
	Mspid string
	Id    string
}

// OUIdentifier 组织单元的身份标识符。
type OUIdentifier struct {
	// CertifiersIdentifier 一连串证书链的标识符（哈希值），由同一个机构签发的不同证书，
	// 所计算出来的 CertifiersIdentifier 是一样的。
	CertifiersIdentifier []byte
	// OrganizationalUnitIdentifier 组织单元标识符。
	OrganizationalUnitIdentifier string
}

/* ------------------------------------------------------------------------------------------ */

type CSPNewOpts struct {
	Version MSPVersion
}

func (co *CSPNewOpts) GetVersion() MSPVersion {
	return co.Version
}
