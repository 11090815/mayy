package msp

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"time"

	"github.com/11090815/mayy/csp"
	"github.com/11090815/mayy/csp/signer"
	"github.com/11090815/mayy/csp/softimpl/ecdsa"
	"github.com/11090815/mayy/csp/softimpl/hash"
	"github.com/11090815/mayy/errors"
	"github.com/11090815/mayy/protobuf/pmsp"
	"google.golang.org/protobuf/proto"
)

var (
	oidExtensionSubjectAltName  = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}
)

type setupFunc func(conf *pmsp.MayyMSPConfig) error

type satisfiesPrincipleInternalFuncType func(id Identity, principle *pmsp.MSPPrinciple) error

// validateIdentityOUsFuncType 是一个函数类型，此类函数用于验证 identity 的组织单元 OUs。
type validateIdentityOUsFuncType func(id *identity) error

type setupAdminsInternalFuncType func(conf *pmsp.MayyMSPConfig) error

type mspImpl struct {
	// identifier 此 msp 的标识符。
	identifier string
	version    MSPVersion

	// opts 提供用于验证 msp 成员的 x509 证书的选项。
	opts *x509.VerifyOptions

	// 在初始化 msp 时，会将 rootCerts 中的每个 root CA 和 intermediateCerts 中的每个 intermediate CA 的所有父级证书加入到 certificationTreeInternalNodesMap 中。
	certificationTreeInternalNodesMap map[string]bool

	// rootCerts 罗列了所有我们信任的 CA 证书。
	rootCerts []Identity

	// intermediateCerts 罗列了所有我们信任的中级 CA 证书。
	intermediateCerts []Identity

	// admins 管理员列表。
	admins []Identity

	tlsRootCerts [][]byte

	tlsIntermediateCerts [][]byte

	// CRL 证书撤销列表。
	CRL []*x509.RevocationList

	internalSetupFunc setupFunc

	internalSatisfiesPrincipleInternalFunc satisfiesPrincipleInternalFuncType

	internalValidateIdentityOUsFunc validateIdentityOUsFuncType

	internalSetupAdminsFunc setupAdminsInternalFuncType

	ouEnforcement bool

	csp csp.CSP

	cryptoConfig *pmsp.MayyCryptoConfig

	signer SigningIdentity

	ouIdentifiers map[string][][]byte

	clientOU, peerOU, adminOU, ordererOU *OUIdentifier
}

func newCspMsp(version MSPVersion, csp csp.CSP) (MSP, error) {
	mspLogger.Debug("Creating CSP-based MSP instance.")

	m := &mspImpl{
		version: version,
		csp:     csp,
	}

	switch version {
	case MSPv1_0:
		m.internalSetupFunc = m.setupV1_0
		m.internalValidateIdentityOUsFunc = m.validateIdentityOUsV1_0
		m.internalSatisfiesPrincipleInternalFunc = m.satisfiesPrincipleInternalV1_0
		m.internalSetupAdminsFunc = m.setupAdminsV1_0
	default:
		return nil, errors.NewErrorf("invalid msp version %v", version)
	}

	return m, nil
}

/* ------------------------------------------------------------------------------------------ */
// msp exportable

func (msp *mspImpl) SatisfiesPrinciple(id Identity, principle *pmsp.MSPPrinciple) error {
	principles, err := collectPrinciples(principle, msp.GetVersion())
	if err != nil {
		return err
	}
	for _, p := range principles {
		if err = msp.internalSatisfiesPrincipleInternalFunc(id, p); err != nil {
			return err
		}
	}
	return nil
}

func (msp *mspImpl) GetVersion() MSPVersion {
	return msp.version
}

func (msp *mspImpl) GetType() ProviderType {
	return CSP
}

func (msp *mspImpl) GetIdentifier() string {
	return msp.identifier
}

func (msp *mspImpl) GetTLSRootCerts() [][]byte {
	return msp.tlsRootCerts
}

func (msp *mspImpl) GetTLSIntermediateCerts() [][]byte {
	return msp.tlsIntermediateCerts
}

func (msp *mspImpl) GetDefaultSigningIdentity() (SigningIdentity, error) {
	if msp.signer == nil {
		return nil, errors.NewErrorf("msp %s has not specified a signing identity", msp.identifier)
	}
	return msp.signer, nil
}

func (msp *mspImpl) Validate(id Identity) error {
	switch i := id.(type) {
	case *identity:
		return msp.validateIdentity(i)
	default:
		return errors.NewErrorf("identity type %T not recognized", i)
	}
}

func (msp *mspImpl) DeserializeIdentity(serializedId []byte) (Identity, error) {
	serializedIdentity := &pmsp.SerializedIdentity{}
	if err := proto.Unmarshal(serializedId, serializedIdentity); err != nil {
		return nil, err
	}
	if serializedIdentity.Mspid != msp.identifier {
		return nil, errors.NewErrorf("the deserialized identity has different msp id %s against %s", serializedIdentity.Mspid, msp.identifier)
	}

	return msp.deserializeIdentityInternal(serializedIdentity.IdBytes)
}

func (msp *mspImpl) IsWellFormed(identity *pmsp.SerializedIdentity) error {
	cert, err := msp.getCertFromPem(identity.IdBytes)
	if err != nil {
		return err
	}

	if !isECDSASignedCert(cert) {
		return nil
	}

	return isIdentitySignedInCanonicalForm(cert.Signature, identity.Mspid, identity.IdBytes)
}

func (msp *mspImpl) Setup(conf *pmsp.MSPConfig) error {
	if conf == nil {
		return errors.NewError("nil configuration for msp")
	}

	mayyConf := &pmsp.MayyMSPConfig{}
	if err := proto.Unmarshal(conf.Config, mayyConf); err != nil {
		return errors.NewErrorf("invalid configuration for msp, the error is \"%s\"", err)
	}

	msp.identifier = mayyConf.Name
	mspLogger.Debugf("Setting up MSP instance %s.", msp.identifier)

	return msp.internalSetupFunc(mayyConf)
}

/* ------------------------------------------------------------------------------------------ */
// principle

func (msp *mspImpl) satisfiesPrincipleInternalV1_0(id Identity, principle *pmsp.MSPPrinciple) error {
	switch principle.PrincipleClassification {
	case pmsp.MSPPrinciple_ROLE:
		if !msp.ouEnforcement {
			return errors.NewError("node organizational unit option is not activated")
		}
		mspRole := &pmsp.MSPRole{}
		if err := proto.Unmarshal(principle.Principle, mspRole); err != nil {
			return errors.NewErrorf("identity doesn't satisfy principle, the error is \"%s\"", err.Error())
		}
		if mspRole.MspIdentifier != msp.identifier {
			return errors.NewErrorf("the identity is a member of a different msp %s", mspRole.MspIdentifier)
		}
		switch mspRole.Role {
		case pmsp.MSPRole_MEMBER:
			mspLogger.Debugf("MSP checking if identity satisfies member role under msp %s.", msp.identifier)
			return msp.Validate(id)
		case pmsp.MSPRole_CLIENT, pmsp.MSPRole_PEER:
			mspLogger.Debugf("MSP checking if identity satisfies %s role under msp %s.", strings.ToLower(mspRole.Role.String()), msp.identifier)
			if err := msp.Validate(id); err != nil {
				return errors.NewErrorf("the identity %s is not valid under this msp %s", id.(*identity).identityIdentifier.Id, msp.identifier)
			}
			if err := msp.hasOURole(id, mspRole.Role); err != nil {
				return errors.NewErrorf("the identity %s is not an %s under this msp %s", id.(*identity).identityIdentifier.Id, strings.ToLower(mspRole.Role.String()), msp.identifier)
			}
			return nil
		case pmsp.MSPRole_ADMIN:
			mspLogger.Debug("MSP checking if identity has been named explicitly as an admin.")
			if msp.isInAdmins(id.(*identity)) {
				return nil
			}
			mspLogger.Debugf("MSP checking if identity carries the admin organizational unit for msp %s.", msp.identifier)
			if err := msp.Validate(id); err != nil {
				return errors.NewErrorf("the identity %s is not valid under this msp %s", id.(*identity).identityIdentifier.Id, msp.identifier)
			}

			if err := msp.hasOURole(id, pmsp.MSPRole_ADMIN); err != nil {
				return errors.NewErrorf("the identity %s is not an admin under this msp %s", id.(*identity).identityIdentifier.Id, msp.identifier)
			}
			return nil
		case pmsp.MSPRole_ORDERER:
			mspLogger.Debugf("MSP checking if identity satisfies role %s for %s.", mspRole.String(), msp.identifier)
			if err := msp.Validate(id); err != nil {
				return errors.NewErrorf("the identity %s is not valid under msp %s", id.(*identity).identityIdentifier.Id, msp.identifier)
			}
			if err := msp.hasOURole(id, pmsp.MSPRole_ORDERER); err != nil {
				return errors.NewErrorf("the identity %s is not an orderer under this msp %s", id.(*identity).identityIdentifier.Id, msp.identifier)
			}
			return nil
		default:
			return errors.NewErrorf("msp role type %s is not recognized", mspRole.Role.String())
		}
	case pmsp.MSPPrinciple_COMBINED:
		return errors.NewError("combined principles are not supported")
	case pmsp.MSPPrinciple_ANONYMITY:
		mspIdentityAnonymity := &pmsp.MSPIdentityAnonymity{}
		if err := proto.Unmarshal(principle.Principle, mspIdentityAnonymity); err != nil {
			return errors.NewErrorf("identity doesn't satisfy principle, the error is \"%s\"", err.Error())
		}
		switch mspIdentityAnonymity.AnonymityType {
		case pmsp.MSPIdentityAnonymity_ANONYMOUS:
			return errors.NewError("principle is anonymous, but x.509 msp does not support anonymous identities")
		case pmsp.MSPIdentityAnonymity_NOMINAL:
			return nil
		default:
			return errors.NewErrorf("unknown principle anonymity type %s", mspIdentityAnonymity.AnonymityType.String())
		}
	case pmsp.MSPPrinciple_IDENTITY:
		principleId, err := msp.DeserializeIdentity(principle.Principle)
		if err != nil {
			return errors.NewErrorf("invalid identity principle, the error is \"%s\"", err.Error())
		}
		if bytes.Equal(id.(*identity).cert.Raw, principleId.(*identity).cert.Raw) {
			return principleId.Validate()
		}
		return errors.NewError("the identities do not match")
	case pmsp.MSPPrinciple_ORGANIZATION_UNIT:
		organizationalUnit := &pmsp.OrganizationUnit{}
		if err := proto.Unmarshal(principle.Principle, organizationalUnit); err != nil {
			return errors.NewErrorf("identity doesn't satisfy principle, the error is \"%s\"", err.Error())
		}
		if organizationalUnit.MspIdentifier != msp.identifier {
			return errors.NewErrorf("the identity is a member of a different msp %s", organizationalUnit.MspIdentifier)
		}
		if err := msp.Validate(id); err != nil {
			return errors.NewErrorf("identity doesn't satisfy principle, the error is \"%s\"", err.Error())
		}
		for _, ou := range id.GetOrganizationalUnits() {
			if organizationalUnit.OrganizationUnitIdentifier == ou.OrganizationalUnitIdentifier && bytes.Equal(organizationalUnit.CertifiersIdentifier, ou.CertifiersIdentifier) {
				return nil
			}
		}
		return errors.NewError("the identities do not match")
	default:
		return errors.NewErrorf("principle type %s is not recognized", principle.PrincipleClassification.String())
	}
}

// hasOURole 查看给定身份的组织单元 organizational unit 是否被注册在 msp 内。
func (msp *mspImpl) hasOURole(id Identity, mspRole pmsp.MSPRole_MSPRoleType) error {
	if !msp.ouEnforcement {
		return errors.NewError("node organizational unit option is not activated")
	}

	mspLogger.Debugf("MSP %s checking if the identity is a %s.", msp.identifier, mspRole.String())

	switch id := id.(type) {
	case *identity:
		return msp.hasOURoleInternal(id, mspRole)
	default:
		return errors.NewErrorf("identity type %T is not recognized", id)
	}
}

// hasOURoleInternal 查看给定身份的组织单元 organizational unit 是否被注册在 msp 内。
func (msp *mspImpl) hasOURoleInternal(id *identity, mspRole pmsp.MSPRole_MSPRoleType) error {
	var nodeOU *OUIdentifier

	switch mspRole {
	case pmsp.MSPRole_CLIENT:
		nodeOU = msp.clientOU
	case pmsp.MSPRole_PEER:
		nodeOU = msp.peerOU
	case pmsp.MSPRole_ADMIN:
		nodeOU = msp.adminOU
	case pmsp.MSPRole_ORDERER:
		nodeOU = msp.ordererOU
	default:
		return errors.NewErrorf("msp role type %s is not recognized", mspRole.String())
	}

	if nodeOU == nil {
		return errors.NewErrorf("node organizational unit for type %s is not defined in msp %s", mspRole.String(), msp.identifier)
	}

	for _, ou := range id.GetOrganizationalUnits() {
		if ou.OrganizationalUnitIdentifier == nodeOU.OrganizationalUnitIdentifier {
			return nil
		}
	}

	return errors.NewErrorf("the identity does not contain organizational unit for %s", mspRole.String())
}

/* ------------------------------------------------------------------------------------------ */
// get validation chain

// getValidationChainForCSPIdentity 返回 *identity.cert 的证书验证链。
func (msp *mspImpl) getValidationChainForCSPIdentity(id *identity) ([]*x509.Certificate, error) {
	if id.cert.IsCA {
		return nil, errors.NewError("ca certificate cannot be used as an identity")
	}

	return msp.getValidationChain(id.cert, false)
}

// getValidationChain 此方法传入的第二个参数 isIntermediateChain 是一个布尔值，用于指示 cert 是否是一个中级 CA 证书。
// 如果是中级 CA 证书，那么此证书是不能出现在 certificationTreeInternalNodesMap 里面的。如果 cert 不是中级 CA 证书，
// 那么 cert 一般是一个 identity 的证书，cert 的父级证书也不应该出现在 certificationTreeInternalNodesMap 里面。在
// 满足以上条件后，返回 cert 的证书验证链。
func (msp *mspImpl) getValidationChain(cert *x509.Certificate, isIntermediateChain bool) ([]*x509.Certificate, error) {
	validationChain, err := msp.getUniqueValidationChain(cert, msp.getValidityOptsForCert(cert))
	if err != nil {
		return nil, err
	}

	if len(validationChain) < 2 {
		return nil, errors.NewErrorf("expected a chain of length at least 2, but got %d", len(validationChain))
	}

	intermediatePosition := 1
	if isIntermediateChain {
		intermediatePosition = 0
	}
	// 为 client、peer、admin 和 orderer 等 identity 签发证书的中级证书不应该存在于 certificationTreeInternalNodesMap 这里面。
	if msp.certificationTreeInternalNodesMap[string(validationChain[intermediatePosition].Raw)] {
		return nil, errors.NewError("invalid validation chain, parent certificate should be a leaf of the certification tree")
	}

	return validationChain, nil
}

// getUniqueValidationChain 获取证书的验证链。
func (msp *mspImpl) getUniqueValidationChain(cert *x509.Certificate, opts x509.VerifyOptions) ([]*x509.Certificate, error) {
	validationChains, err := cert.Verify(opts) // Verify 的用法可以参考 certificate_test.go 中的测试案例 TestCertificateVerify
	if err != nil {
		panic(err)
		// return nil, errors.NewErrorf("failed verifying the given certificate against verify options %v, the error is \"%s\"", opts, err.Error())
	}

	if len(validationChains) != 1 {
		return nil, errors.NewError("msp only supports a single validation chain")
	}

	return validationChains[0], nil
}

/* ------------------------------------------------------------------------------------------ */
// validate identity

// validateIdentity 首先判断给定的 *identity.cert 是否被撤销，若被撤销，则返回错误，否则继续验证
// 此身份所具有的组织单元 organizational unit 是否在 msp 内存在，如果 msp.ouEnforcement == true，
// 则直接返回 nil-error，否则如果 *identity 所具有的 organizational unit 不存在于 msp 内，则会返
// 回错误。接着检查 identity 的 organizational unit 是否与 msp 内的 client、peer、admin 和 orderer
// 中的其中一个相匹配，如果不匹配，返回错误，如果匹配多个也返回错误。
func (msp *mspImpl) validateIdentity(id *identity) error {
	id.validationMutex.Lock()
	defer id.validationMutex.Unlock()

	if id.validated {
		return id.validationErr
	}

	id.validated = true

	validationChain, err := msp.getValidationChainForCSPIdentity(id)
	if err != nil {
		id.validationErr = err
		mspLogger.Errorf("Failed validating identity %s, because %s.", id.identityIdentifier.Id, err.Error())
		return errors.NewErrorf("failed validating identity %s, the error is \"%s\"", id.identityIdentifier.Id, err.Error())
	}

	if err = msp.validateCertAgainstChain(id.cert, validationChain); err != nil {
		id.validationErr = err
		mspLogger.Errorf("Failed validating identity %s, because %s.", id.identityIdentifier.Id, err.Error())
		return errors.NewErrorf("failed validating identity %s, the error is \"%s\"", id.identityIdentifier.Id, err.Error())
	}

	if err = msp.internalValidateIdentityOUsFunc(id); err != nil {
		id.validationErr = err
		mspLogger.Errorf("Failed validating identity %s, because %s.", id.identityIdentifier.Id, err.Error())
		return errors.NewErrorf("failed validating identity %s, the error is \"%s\"", id.identityIdentifier.Id, err.Error())
	}

	return nil
}

func (msp *mspImpl) validateIdentityOUsV1_0(id *identity) error {
	if len(msp.ouIdentifiers) > 0 {
		found := false

		for _, ou := range id.GetOrganizationalUnits() {
			certifiersIdentifiers, exists := msp.ouIdentifiers[ou.OrganizationalUnitIdentifier]
			if exists {
				for _, certifiersIdentifier := range certifiersIdentifiers {
					if bytes.Equal(certifiersIdentifier, ou.CertifiersIdentifier) {
						found = true
						break
					}
				}
			}
		}

		if !found {
			if len(id.GetOrganizationalUnits()) == 0 {
				return errors.NewErrorf("the identity certificate %s does not contain an organizational unit", id.cert.SerialNumber.String())
			}
			return errors.NewErrorf("noneof the identity's organizational units are in the msp %s", msp.identifier)
		}
	}

	if !msp.ouEnforcement {
		return nil
	}

	counter := 0
	validOUs := make(map[string]*OUIdentifier)
	if msp.clientOU != nil {
		validOUs[msp.clientOU.OrganizationalUnitIdentifier] = msp.clientOU
	}
	if msp.peerOU != nil {
		validOUs[msp.peerOU.OrganizationalUnitIdentifier] = msp.peerOU
	}
	if msp.adminOU != nil {
		validOUs[msp.adminOU.OrganizationalUnitIdentifier] = msp.adminOU
	}
	if msp.ordererOU != nil {
		validOUs[msp.ordererOU.OrganizationalUnitIdentifier] = msp.ordererOU
	}
	for _, ou := range id.GetOrganizationalUnits() {
		nodeOU, exists := validOUs[ou.OrganizationalUnitIdentifier]
		if !exists {
			continue
		}
		if len(nodeOU.CertifiersIdentifier) != 0 && !bytes.Equal(nodeOU.CertifiersIdentifier, ou.CertifiersIdentifier) {
			return errors.NewErrorf("the identity's certifiers identifier does not match to node organizational unit")
		}
		counter++
		if counter > 1 {
			break
		}
	}

	if counter == 0 {
		return errors.NewErrorf("the identity %s does not have an organizational unit that resolves to client, peer, admin and orderer", id.identityIdentifier)
	}
	if counter > 1 {
		return errors.NewErrorf("the identity %s must only have one organizational unit that resolves to client, peer, admin or orderer", id.identityIdentifier.Id)
	}

	return nil
}

// validateCAIdentity 获取 *identity.cert 的证书验证链，然后从证书验证链 validationChain 中获取证书 cert 的父级证书，提
// 取父级证书的 ski，然后遍历 msp 的撤销证书列表 CRL，获取每个撤销证书的 aki（aki 是撤销证书的父级证书的 ski），如果 aki 与
// 前面的 ski 相等，则说明 cert 的父级证书产生了撤销证书，遍历那些撤销证书，如果其中有撤销证书的序列号等于 cert 的序列号，则
// 说明此 cert 已被撤销，需要返回对应的错误，否则此方法返回 nil-error。
func (msp *mspImpl) validateCAIdentity(id *identity) error {
	if id.cert.IsCA {
		validationChain, err := msp.getUniqueValidationChain(id.cert, msp.getValidityOptsForCert(id.cert))
		if err != nil {
			return errors.NewErrorf("failed validating ca identity, the error is \"%s\"", err.Error())
		}
		if len(validationChain) == 1 {
			// 根证书，无需再做验证
			return nil
		}
		return msp.validateCertAgainstChain(id.cert, validationChain)
	} else {
		return errors.NewError("only ca identity can be validated against function validateCAIdentity")
	}
}

func (msp *mspImpl) validateTLSCACertificate(cert *x509.Certificate, opts x509.VerifyOptions) error {
	if cert.IsCA {
		validationChain, err := msp.getUniqueValidationChain(cert, opts)
		if err != nil {
			return errors.NewErrorf("failed validating tls ca certificate, the error is \"%s\"", err.Error())
		}

		if len(validationChain) == 1 {
			// 根证书，无需再验证
			return nil
		}

		return msp.validateCertAgainstChain(cert, validationChain)
	} else {
		return errors.NewError("only tls ca certificate can be validated against function validateTLSCACertificate")
	}
}

// validateCertAgainstChain 从证书验证链 validationChain 中获取证书 cert 的父级证书，提取父级证书的 ski，然后遍历 msp 的
// 撤销证书列表 CRL，获取每个撤销证书的 aki（aki 是撤销证书的父级证书的 ski），如果 aki 与前面的 ski 相等，则说明 cert 的父
// 级证书产生了撤销证书，遍历那些撤销证书，如果其中有撤销证书的序列号等于 cert 的序列号，则说明此 cert 已被撤销，需要返回对应
// 的错误，否则此方法返回 nil-error。
func (msp *mspImpl) validateCertAgainstChain(cert *x509.Certificate, validationChain []*x509.Certificate) error {
	ski, err := getSubjectKeyIdentifierFromCert(validationChain[1]) // 获取为 identity 背书的证书的 ski。
	if err != nil {
		return errors.NewErrorf("failed validating identity against calidation chain, the error is \"%s\"", err.Error())
	}

	for _, rl := range msp.CRL {
		aki, err := getAuthorityKeyIdentifierFromCrl(rl)
		if err != nil {
			return errors.NewErrorf("failed validating identity against calidation chain, the error is \"%s\"", err.Error())
		}

		if bytes.Equal(ski, aki) {
			// 被撤销的证书由为 identity 背书的证书机构签发。
			for _, rc := range rl.RevokedCertificates {
				if rc.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					return errors.NewErrorf("the certificate %s has been revoked", cert.SerialNumber.String())
				}
			}
		}
	}

	return nil
}

/* ------------------------------------------------------------------------------------------ */
// setup msp

func (msp *mspImpl) setupV1_0(conf *pmsp.MayyMSPConfig) error {
	if err := msp.setupCrypto(conf); err != nil {
		return err
	}

	if err := msp.setupCAs(conf); err != nil {
		return err
	}

	if err := msp.finalizeSetupCAs(); err != nil {
		return err
	}

	if err := msp.setupCRLs(conf); err != nil {
		return err
	}

	if err := msp.setupSigningIdentity(conf); err != nil {
		return err
	}

	if err := msp.setupTLSCAs(conf); err != nil {
		return err
	}

	if err := msp.setupOUs(conf); err != nil {
		return err
	}

	if err := msp.setupAdmins(conf); err != nil {
		return err
	}

	if !msp.ouEnforcement {
		for i, admin := range msp.admins {
			err := admin.Validate()
			if err != nil {
				errors.NewErrorf("the no.%d admin %s is invalid", i, admin.(*identity).identityIdentifier.Id)
			}
		}
		return nil
	}

	for i, admin := range msp.admins {
		err1 := msp.hasOURole(admin, pmsp.MSPRole_CLIENT)
		err2 := msp.hasOURole(admin, pmsp.MSPRole_ADMIN)
		if err1 != nil && err2 != nil {
			return errors.NewErrorf("the no.%d admin is invalid: [err1: %s] [err2: %s]", i, err1, err2)
		}
	}

	return nil
}

// setupCrypto 设置计算签名时，计算哈希值所用的哈希算法，设置计算身份标识符时所用的哈希算法。
func (msp *mspImpl) setupCrypto(conf *pmsp.MayyMSPConfig) error {
	msp.cryptoConfig = conf.CryptoConfig
	if msp.cryptoConfig == nil {
		msp.cryptoConfig = &pmsp.MayyCryptoConfig{
			SignatureHashFunction:          hash.SHA256,
			IdentityIdentifierHashFunction: hash.SHA256,
		}
	}
	if msp.cryptoConfig.SignatureHashFunction == "" {
		msp.cryptoConfig.SignatureHashFunction = hash.SHA256
	}
	if msp.cryptoConfig.IdentityIdentifierHashFunction == "" {
		msp.cryptoConfig.IdentityIdentifierHashFunction = hash.SHA256
	}

	return nil
}

func (msp *mspImpl) setupCAs(conf *pmsp.MayyMSPConfig) error {
	if len(conf.RootCerts) == 0 {
		return errors.NewError("expected at least one ca certificate")
	}

	// 构造 VerifyOptions，以便对 root CA 和 intermediate CA 进行签名净化
	msp.opts = &x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		Intermediates: x509.NewCertPool(),
	}
	for _, rootCert := range conf.RootCerts {
		if !msp.opts.Roots.AppendCertsFromPEM(rootCert) {
			return errors.NewError("failed adding root ca certificate")
		}
	}
	for _, intermediateCert := range conf.IntermediateCerts {
		if !msp.opts.Intermediates.AppendCertsFromPEM(intermediateCert) {
			return errors.NewError("failed adding intermediate ca certificate")
		}
	}
	msp.rootCerts = make([]Identity, 0)
	msp.intermediateCerts = make([]Identity, 0)
	for _, rootCert := range conf.RootCerts {
		id, _, err := msp.getIdentityFromCert(rootCert) // 会对 root CA 证书里的签名进行净化
		if err != nil {
			return errors.NewErrorf("failed adding root ca certificate, the error is \"%s\"", err.Error())
		}
		msp.rootCerts = append(msp.rootCerts, id)
	}
	for _, intermediateCert := range conf.IntermediateCerts {
		id, _, err := msp.getIdentityFromCert(intermediateCert) // 会对 intermediate CA 证书里的签名进行净化
		if err != nil {
			return errors.NewErrorf("failed adding intermediate ca certificate, the error is \"%s\"", err.Error())
		}
		msp.intermediateCerts = append(msp.intermediateCerts, id)
	}

	// 将经历过签名净化的 root CA 和 intermediate CA 加入到 VerifyOptions 中
	msp.opts = &x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		Intermediates: x509.NewCertPool(),
	}
	for _, id := range msp.rootCerts {
		msp.opts.Roots.AddCert(id.(*identity).cert)
	}
	for _, id := range msp.intermediateCerts {
		msp.opts.Intermediates.AddCert(id.(*identity).cert)
	}

	return nil
}

func (msp *mspImpl) finalizeSetupCAs() error {
	for _, id := range append(append([]Identity{}, msp.rootCerts...), msp.intermediateCerts...) {
		if err := msp.validateCAIdentity(id.(*identity)); err != nil {
			return errors.NewErrorf("failed setting up ca, the error is \"%s\"", err.Error())
		}
	}

	msp.certificationTreeInternalNodesMap = make(map[string]bool)
	for _, id := range append([]Identity{}, msp.intermediateCerts...) {
		chain, err := msp.getUniqueValidationChain(id.(*identity).cert, msp.getValidityOptsForCert(id.(*identity).cert))
		if err != nil {
			return err
		}

		for i := 1; i < len(chain); i++ {
			msp.certificationTreeInternalNodesMap[string(chain[i].Raw)] = true
		}
	}

	return nil
}

func (msp *mspImpl) setupAdmins(conf *pmsp.MayyMSPConfig) error {
	return msp.internalSetupAdminsFunc(conf)
}

func (msp *mspImpl) setupAdminsV1_0(conf *pmsp.MayyMSPConfig) error {
	msp.admins = make([]Identity, len(conf.Admins))
	for i, adminCert := range conf.Admins {
		id, _, err := msp.getIdentityFromCert(adminCert)
		if err != nil {
			return err
		}
		msp.admins[i] = id
	}

	if len(msp.admins) == 0 && (!msp.ouEnforcement || msp.adminOU == nil) {
		return errors.NewError("administrators must be declared when no admin organizational unit classification is set")
	}

	return nil
}

func (msp *mspImpl) setupCRLs(conf *pmsp.MayyMSPConfig) error {
	msp.CRL = make([]*x509.RevocationList, len(conf.RevocationList))
	for i, crlBytes := range conf.RevocationList {
		crl, err := x509.ParseRevocationList(crlBytes)
		if err != nil {
			return errors.NewErrorf("failed setting up crls, the error is \"%s\"", err.Error())
		}

		isECDSASignatureAlgorithm := crl.SignatureAlgorithm == x509.ECDSAWithSHA1 ||
			crl.SignatureAlgorithm == x509.ECDSAWithSHA256 ||
			crl.SignatureAlgorithm == x509.ECDSAWithSHA384 ||
			crl.SignatureAlgorithm == x509.ECDSAWithSHA512

		if isECDSASignatureAlgorithm {
			r, s, err := ecdsa.UnmarshalECDSASignature(crl.Signature)
			if err != nil {
				return err
			}
			sig, err := ecdsa.MarshalECDSASignature(r, s)
			if err != nil {
				return err
			}
			crl.Signature = sig
		}
		msp.CRL[i] = crl
	}

	return nil
}

func (msp *mspImpl) setupSigningIdentity(conf *pmsp.MayyMSPConfig) error {
	if conf.SigningIdentity != nil {
		sid, err := msp.getSigningIdentityFromConf(conf.SigningIdentity)
		if err != nil {
			return err
		}

		expirationTime := sid.ExpiresAt()
		now := time.Now()
		if expirationTime.After(now) {
			mspLogger.Debugf("Signing identity %s will expire at %s.", sid.(*signingIdentity).identity.identityIdentifier.Id, expirationTime.Format(time.RFC3339Nano))
		} else if expirationTime.IsZero() {
			mspLogger.Warnf("Signing identity %s did not specify the expiration time.", sid.(*signingIdentity).identity.identityIdentifier.Id)
		} else {
			mspLogger.Errorf("Signing identity %s has expired.", sid.(*signingIdentity).identity.identityIdentifier.Id)
			return errors.NewErrorf("signing identity %s has expired %.2f seconds ago.", sid.GetPublicVersion().(*identity).identityIdentifier.Mspid, now.Sub(expirationTime).Seconds())
		}
		msp.signer = sid
	}
	return nil
}

func (msp *mspImpl) setupTLSCAs(conf *pmsp.MayyMSPConfig) error {
	opts := &x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		Intermediates: x509.NewCertPool(),
	}

	msp.tlsRootCerts = make([][]byte, len(conf.TlsRootCerts))
	rootCerts := make([]*x509.Certificate, len(conf.TlsRootCerts))
	for i, tlsRoorCert := range conf.TlsRootCerts {
		cert, err := msp.getCertFromPem(tlsRoorCert)
		if err != nil {
			return err
		}
		msp.tlsRootCerts[i] = tlsRoorCert
		opts.Roots.AddCert(cert)
		rootCerts[i] = cert
	}

	msp.tlsIntermediateCerts = make([][]byte, len(conf.TlsIntermediateCerts))
	intermediateCerts := make([]*x509.Certificate, len(conf.TlsIntermediateCerts))
	for i, tlsIntermediateCert := range conf.TlsIntermediateCerts {
		cert, err := msp.getCertFromPem(tlsIntermediateCert)
		if err != nil {
			return err
		}
		msp.tlsIntermediateCerts[i] = tlsIntermediateCert
		opts.Intermediates.AddCert(cert)
		intermediateCerts[i] = cert
	}

	for _, cert := range append(append([]*x509.Certificate{}, rootCerts...), intermediateCerts...) {
		if !cert.IsCA {
			return errors.NewError("not a ca certificate")
		}

		opts.CurrentTime = cert.NotBefore.Add(time.Second)
		if err := msp.validateTLSCACertificate(cert, *opts); err != nil {
			return err
		}
	}

	return nil
}

func (msp *mspImpl) setupOUs(conf *pmsp.MayyMSPConfig) error {
	msp.ouIdentifiers = make(map[string][][]byte)
	for _, ou := range conf.OrganizationUnitIdentifiers {
		certifiersIdentifier, err := msp.getCertifiersIdentifier(ou.Certificate)
		if err != nil {
			return err
		}

		isDuplicate := false
		for _, id := range msp.ouIdentifiers[ou.OrganizationUnitIdentifier] {
			if bytes.Equal(id, certifiersIdentifier) {
				mspLogger.Warnf("Duplicate certificates found in ou identifier %s.", ou.OrganizationUnitIdentifier)
				isDuplicate = true
				break
			}
		}

		if !isDuplicate {
			msp.ouIdentifiers[ou.OrganizationUnitIdentifier] = append(msp.ouIdentifiers[ou.OrganizationUnitIdentifier], certifiersIdentifier)
		}
	}

	if conf.MayyNodeOus == nil {
		msp.ouEnforcement = false
		return nil
	}
	msp.ouEnforcement = conf.MayyNodeOus.Enable

	counter := 0

	// client organizational unit
	if conf.MayyNodeOus.ClientOuIdentifier != nil {
		msp.clientOU = &OUIdentifier{
			OrganizationalUnitIdentifier: conf.MayyNodeOus.ClientOuIdentifier.OrganizationUnitIdentifier,
		}
		if len(conf.MayyNodeOus.ClientOuIdentifier.Certificate) != 0 {
			certifiersIdentifier, err := msp.getCertifiersIdentifier(conf.MayyNodeOus.ClientOuIdentifier.Certificate)
			if err != nil {
				return err
			}
			msp.clientOU.CertifiersIdentifier = certifiersIdentifier
		}
		counter++
	} else {
		msp.clientOU = nil
	}

	// peer organizational unit
	if conf.MayyNodeOus.PeerOuIdentifier != nil {
		msp.peerOU = &OUIdentifier{
			OrganizationalUnitIdentifier: conf.MayyNodeOus.PeerOuIdentifier.OrganizationUnitIdentifier,
		}
		if len(conf.MayyNodeOus.PeerOuIdentifier.Certificate) != 0 {
			certifiersIdentifier, err := msp.getCertifiersIdentifier(conf.MayyNodeOus.PeerOuIdentifier.Certificate)
			if err != nil {
				return err
			}
			msp.peerOU.CertifiersIdentifier = certifiersIdentifier
		}
		counter++
	} else {
		msp.peerOU = nil
	}

	// admin organizational unit
	if conf.MayyNodeOus.AdminOuIdentifier != nil {
		msp.adminOU = &OUIdentifier{
			OrganizationalUnitIdentifier: conf.MayyNodeOus.AdminOuIdentifier.OrganizationUnitIdentifier,
		}
		if len(conf.MayyNodeOus.AdminOuIdentifier.Certificate) != 0 {
			certifiersIdentifier, err := msp.getCertifiersIdentifier(conf.MayyNodeOus.AdminOuIdentifier.Certificate)
			if err != nil {
				return err
			}
			msp.adminOU.CertifiersIdentifier = certifiersIdentifier
		}
		counter++
	} else {
		msp.adminOU = nil
	}

	// orderer organizational unit
	if conf.MayyNodeOus.OrdererOuIdentifier != nil {
		msp.ordererOU = &OUIdentifier{
			OrganizationalUnitIdentifier: conf.MayyNodeOus.OrdererOuIdentifier.OrganizationUnitIdentifier,
		}
		if len(conf.MayyNodeOus.OrdererOuIdentifier.Certificate) != 0 {
			certifiersIdentifier, err := msp.getCertifiersIdentifier(conf.MayyNodeOus.OrdererOuIdentifier.Certificate)
			if err != nil {
				return err
			}
			msp.ordererOU.CertifiersIdentifier = certifiersIdentifier
		}
		counter++
	} else {
		msp.ordererOU = nil
	}

	if counter == 0 {
		msp.ouEnforcement = false
	}

	return nil
}

/* ------------------------------------------------------------------------------------------ */
// utils

func (msp *mspImpl) getValidityOptsForCert(cert *x509.Certificate) x509.VerifyOptions {
	return x509.VerifyOptions{
		Roots:         msp.opts.Roots,
		DNSName:       msp.opts.DNSName,
		Intermediates: msp.opts.Intermediates,
		KeyUsages:     msp.opts.KeyUsages,
		CurrentTime:   cert.NotBefore.Add(time.Second),
	}
}

// getCertifiersIdentifier 给定一个证书的 PEM 格式编码的字节数组，此证书必须是 root ca
// 证书或 intermediate ca 证书，不然会报错。
func (msp *mspImpl) getCertifiersIdentifier(certRaw []byte) ([]byte, error) {
	cert, err := msp.getCertFromPem(certRaw)
	if err != nil {
		return nil, err
	}

	cert, err = msp.sanitizeCert(cert)
	if err != nil {
		return nil, err
	}

	found := false
	root := false

	for _, rootCert := range msp.rootCerts {
		if rootCert.(*identity).cert.Equal(cert) {
			found = true
			root = true
			break
		}
	}
	if !found {
		for _, intermediateCert := range msp.intermediateCerts {
			if intermediateCert.(*identity).cert.Equal(cert) {
				found = true
				break
			}
		}
	}
	if !found {
		return nil, errors.NewErrorf("failed adding certificate %s, it is not in root or intermediate certificates", cert.SerialNumber.String())
	}

	var chain []*x509.Certificate
	if root {
		chain = []*x509.Certificate{cert}
	} else {
		// 获取中级 CA 证书的证书链。
		chain, err = msp.getValidationChain(cert, true)
		if err != nil {
			return nil, err
		}
	}

	return msp.getCertificationChainIdentifierFromChain(chain)
}

// getCertificationChainIdentifier 方法介绍：
//
//	入参-1： id Identity
//	返回参数-1：[]byte；返回参数-2：error
//	-----------------------------------
//	入参-1 是 Identity 接口，目前仅支持 *identity 类型，其他类型的会报类型错误。getCertificationChainIdentifier 方法首先会把
//	id 显式类型转化为 *identity，然后判断 *identity.cert 是否是一个 CA 证书，如果是的话，则会返回错误，因为 CA 证书不能用作某个
//	identity 的证书。随后判断 *identity.cert 的父级证书是否是证书树中的叶子节点，如果不是的话，则会报错，因为为 client、peer、
//	orderer 和 admin 等 identity 签发证书的上级证书不能是 msp 内注册的 root CAs 和 intermediate CAs 的父级证书。最后，根据
//	*identity.cert的证书链计算其哈希值：digest <- Hash(parent | grandparent | ...)，注意这里在计算证书链的哈希值时，没有考虑
//	 *identity.cert，这样一来，getCertificationChainIdentifier 为不同的 Identity 计算出来的 certification identifier 可能是
//	相同的，前提是这些Identity 是由相同的父级证书签发的。
func (msp *mspImpl) getCertificationChainIdentifier(id Identity) ([]byte, error) {
	switch id := id.(type) {
	case *identity:
		if id == nil {
			return nil, errors.NewError("invalid identity, nil pointer")
		}

		if msp.opts == nil {
			return nil, errors.NewError("there is no verify options for certificate in msp")
		}

		if id.cert.IsCA {
			return nil, errors.NewError("ca certificate cannot be used as the identity's certificate")
		}

		chain, err := msp.getValidationChain(id.cert, false)
		if err != nil {
			return nil, errors.NewErrorf("failed getting certification chain identifier, the error is \"%s\"", err.Error())
		}
		return msp.getCertificationChainIdentifierFromChain(chain[1:]) // 过滤掉自己的证书
	default:
		return nil, errors.NewErrorf("failed getting certification chain identifier, identity type %T not recognized", id)
	}
}

func (msp *mspImpl) getCertificationChainIdentifierFromChain(chain []*x509.Certificate) ([]byte, error) {
	hashOpt, err := hash.GetHashOpt(msp.cryptoConfig.IdentityIdentifierHashFunction)
	if err != nil {
		return nil, errors.NewErrorf("failed getting certification chain identifier, the error is \"%s\"", err.Error())
	}
	hashFunc, err := msp.csp.GetHash(hashOpt)
	if err != nil {
		return nil, errors.NewErrorf("failed getting certification chain identifier, the error is \"%s\"", err.Error())
	}
	for i := 0; i < len(chain); i++ {
		hashFunc.Write(chain[i].Raw)
	}
	return hashFunc.Sum(nil), nil
}

func (msp *mspImpl) getCertFromPem(idBytes []byte) (*x509.Certificate, error) {
	if len(idBytes) == 0 {
		return nil, errors.NewError("nil identity certificate")
	}
	block, _ := pem.Decode(idBytes)
	if block == nil {
		return nil, errors.NewErrorf("invalid identity certificate: %s", string(idBytes))
	}
	return x509.ParseCertificate(block.Bytes)
}

func (msp *mspImpl) getIdentityFromCert(certBytes []byte) (Identity, csp.Key, error) {
	cert, err := msp.getCertFromPem(certBytes)
	if err != nil {
		return nil, nil, err
	}

	pk, err := msp.csp.KeyImport(cert, &ecdsa.ECDSAX509PublicKeyImportOpts{Temporary: true})
	if err != nil {
		return nil, nil, err
	}

	identity, err := newIdentity(cert, pk, msp)
	if err != nil {
		return nil, nil, err
	}

	return identity, pk, nil
}

func (msp *mspImpl) isInAdmins(id *identity) bool {
	for _, admin := range msp.admins {
		if bytes.Equal(id.cert.Raw, admin.(*identity).cert.Raw) {
			return true
		}
	}
	return false
}

func (msp *mspImpl) deserializeIdentityInternal(certBytes []byte) (Identity, error) {
	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	pk, err := msp.csp.KeyImport(cert, &ecdsa.ECDSAX509PublicKeyImportOpts{})
	if err != nil {
		return nil, err
	}

	return newIdentity(cert, pk, msp)
}

func (msp *mspImpl) getSigningIdentityFromConf(sidInfo *pmsp.SigningIdentityInfo) (SigningIdentity, error) {
	if sidInfo == nil {
		return nil, errors.NewError("nil signing identity info")
	}
	id, pk, err := msp.getIdentityFromCert(sidInfo.PublicSigner)
	if err != nil {
		return nil, err
	}

	sk, err := msp.csp.GetKey(pk.SKI())
	if err != nil {
		mspLogger.Errorf("Cannot find the private key against ski %x.", pk.SKI())
		if sidInfo.PrivateSigner.KeyIdentifier != hex.EncodeToString(pk.SKI()) {
			return nil, errors.NewErrorf("subject key identifier mismatches: \"%s\" <=> \"%s\"", sidInfo.PrivateSigner.KeyIdentifier, hex.EncodeToString(pk.SKI()))
		}
		if sidInfo.PrivateSigner == nil || sidInfo.PrivateSigner.KeyMaterial == nil {
			return nil, errors.NewError("key material not found in SigningIdentityInfo")
		}

		block, _ := pem.Decode(sidInfo.PrivateSigner.KeyMaterial)
		if block == nil {
			return nil, errors.NewErrorf("invalid key material: %s", string(sidInfo.PrivateSigner.KeyMaterial))
		}
		sk, err = msp.csp.KeyImport(block.Bytes, &ecdsa.ECDSAPrivateKeyImportOpts{Temporary: true})
		if err != nil {
			return nil, err
		}
		if hex.EncodeToString(sk.SKI()) != hex.EncodeToString(pk.SKI()) {
			return nil, errors.NewErrorf("subject key identifier mismatches: \"%s\" <=> \"%s\"", hex.EncodeToString(sk.SKI()), hex.EncodeToString(pk.SKI()))
		}
	}

	peerSigner, err := signer.NewSigner(msp.csp, sk)
	if err != nil {
		return nil, err
	}
	return newSigningIdentity(id.(*identity).cert, pk, peerSigner, msp)
}

func (msp *mspImpl) sanitizeCert(cert *x509.Certificate) (*x509.Certificate, error) {
	var err error

	if isECDSASignedCert(cert) {
		isRootCACert := false
		validityOpts := msp.getValidityOptsForCert(cert)
		if cert.IsCA && cert.CheckSignatureFrom(cert) == nil {
			cert, err = sanitizeECDSASignedCert(cert, cert) // 净化签名
			if err != nil {
				return nil, err
			}
			isRootCACert = true
			validityOpts.Roots = x509.NewCertPool()
			validityOpts.Roots.AddCert(cert)
		}
		chain, err := msp.getUniqueValidationChain(cert, validityOpts)
		if err != nil {
			return nil, err
		}

		if isRootCACert {
			return cert, nil
		}

		if len(chain) <= 1 {
			return nil, errors.NewErrorf("failed to traverse certificate verification chain for leaf or intermediate certificate, with subject %s", cert.Subject)
		}
		return sanitizeECDSASignedCert(cert, chain[1])
	}
	return cert, nil
}
