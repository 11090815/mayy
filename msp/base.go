package msp

type MSPVersion int

const (
	MSPv1_0 MSPVersion = iota
	MSPv1_1
	MSPv1_3
	MSPv1_4_3
)

/* ------------------------------------------------------------------------------------------ */

type ProviderType int

const (
	MAYY ProviderType = iota
	OTHER
)

var mspTypeStrings = map[ProviderType]string{
	MAYY:  "csp",
	OTHER: "other",
}

func ProviderTypeToString(id ProviderType) string {
	if res, found := mspTypeStrings[id]; found {
		return res
	}
	return mspTypeStrings[OTHER]
}

var Options = map[string]NewOpts{
	ProviderTypeToString(MAYY): &CSPNewOpts{Version: MSPv1_4_3},
}

/* ------------------------------------------------------------------------------------------ */

// IdentityIdentifier 表示身份标识，由 msp_id 和自己的身份 id 组成。
type IdentityIdentifier struct {
	Mspid string
	Id    string
}

// OUIdentifier 组织单元的身份标识符。
type OUIdentifier struct {
	// CertifiersIdentifier 证书的标识符（哈希值）。
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
