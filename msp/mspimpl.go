package msp

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"strings"
	"time"

	"github.com/11090815/mayy/csp"
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

type satisfiesPrincipleInternalFuncType func(id Identity, principle *pmsp.MSPPrinciple) error

// validateIdentityOUsFuncType 是一个函数类型，此类函数用于验证 identity 的组织单元 OUs。
type validateIdentityOUsFuncType func(id *identity) error

type setupAdminsInternalFuncType func(conf *pmsp.MayyMSPConfig) error

type msp struct {
	// identifier 此 msp 的标识符。
	identifier string
	version    MSPVersion

	// opts 提供用于验证 msp 成员的 x509 证书的选项。
	opts *x509.VerifyOptions

	// 在初始化 msp 时，会将 intermediateCerts 中的每个中级证书的所有上级证书加入到 certificationTreeInternalNodesMap 中。
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

	internalSatisfiesPrincipleInternalFunc satisfiesPrincipleInternalFuncType

	internalValidateIdentityOUsFunc validateIdentityOUsFuncType

	internalSetupAdmins setupAdminsInternalFuncType

	ouEnforcement bool

	clientOU, peerOU, adminOU, ordererOU *OUIdentifier

	csp csp.CSP

	cryptoConfig *pmsp.MayyCryptoConfig

	signer SigningIdentity
}

/* ------------------------------------------------------------------------------------------ */
// msp exportable

func (msp *msp) SatisfiesPrinciple(id Identity, principle *pmsp.MSPPrinciple) error {
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

func (msp *msp) GetVersion() MSPVersion {
	return msp.version
}

func (msp *msp) GetType() ProviderType {
	return MAYY
}

func (msp *msp) GetIdentifier() string {
	return msp.identifier
}

func (msp *msp) GetTLSRootCerts() [][]byte {
	return msp.tlsRootCerts
}

func (msp *msp) GetTLSIntermediateCerts() [][]byte {
	return msp.tlsIntermediateCerts
}

func (msp *msp) GetDefaultSigningIdentity() (SigningIdentity, error) {
	if msp.signer == nil {
		return nil, errors.NewErrorf("msp %s has not specified a signing identity", msp.identifier)
	}
	return msp.signer, nil
}

func (msp *msp) Validate(id Identity) error {
	switch i := id.(type) {
	case *identity:
		return msp.validateIdentity(i)
	default:
		return errors.NewErrorf("identity type %T not recognized", i)
	}
}

func (msp *msp) DeserializeIdentity(serializedId []byte) (Identity, error) {
	serializedIdentity := &pmsp.SerializedIdentity{}
	if err := proto.Unmarshal(serializedId, serializedIdentity); err != nil {
		return nil, err
	}
	if serializedIdentity.Mspid != msp.identifier {
		return nil, errors.NewErrorf("the deserialized identity has different msp id %s against %s", serializedIdentity.Mspid, msp.identifier)
	}

	return msp.deserializeIdentityInternal(serializedIdentity.IdBytes)
}

func (msp *msp) sanitizeCert(cert *x509.Certificate) (*x509.Certificate, error) {
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

/* ------------------------------------------------------------------------------------------ */
// principle

func (msp *msp) satisfiesPrincipleInternalV1_0(id Identity, principle *pmsp.MSPPrinciple) error {
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
				return errors.NewErrorf("the identity is not valid under this msp %s", id.(*identity).identityIdentifier.Id, msp.identifier)
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
				return errors.NewErrorf("the identity is not valid under this msp %s", id.(*identity).identityIdentifier.Id, msp.identifier)
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

func (msp *msp) hasOURole(id Identity, mspRole pmsp.MSPRole_MSPRoleType) error {
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

func (msp *msp) hasOURoleInternal(id *identity, mspRole pmsp.MSPRole_MSPRoleType) error {
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

func (msp *msp) getValidationChainForCSPIdentity(id *identity) ([]*x509.Certificate, error) {
	if id.cert.IsCA {
		return nil, errors.NewError("ca certificate cannot be used as an identity")
	}

	return msp.getValidationChain(id.cert, false)
}

// getValidationChain 此方法传入的第二个参数 isIntermediateChain 是一个布尔值，用于指示此方法的第一个参数 cert 是否是一个 intermediate 证书，
// 如果是的话，那么通过 Verify 方法获得的证书链中的第一个证书，即 cert 本身，必然要存在于 certificationTreeInternalNodesMap 映射中，对此，我
// 们需要做出判断，如果不在，则会返回错误。如果 cert 不是一个 intermediate 证书，则证书链中的第二个证书必然是一个 intermediate 证书，那么，我们
// 依然需要判断证书链中的第二个证书在不在 certificationTreeInternalNodesMap 映射中，如果不在，则会返回错误。
func (msp *msp) getValidationChain(cert *x509.Certificate, isIntermediateChain bool) ([]*x509.Certificate, error) {
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
		return nil, errors.NewErrorf("invalid validation chain, parent certificate should be a leaf of the certification tree")
	}

	return validationChain, nil
}

// getUniqueValidationChain 获取证书的验证链。
func (msp *msp) getUniqueValidationChain(cert *x509.Certificate, opts x509.VerifyOptions) ([]*x509.Certificate, error) {
	validationChains, err := cert.Verify(opts) // Verify 的用法可以参考 certificate_test.go 中的测试案例 TestCertificateVerify
	if err != nil {
		return nil, errors.NewErrorf("failed verifying the given certificate against verify options %v, the error is \"%s\"", opts, err.Error())
	}

	if len(validationChains) != 1 {
		return nil, errors.NewError("msp only supports a single validation chain")
	}

	return validationChains[0], nil
}

/* ------------------------------------------------------------------------------------------ */
// validate identity

func (msp *msp) validateIdentity(id *identity) error {
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

func (msp *msp) validateCAIdentity(id *identity) error {
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

func (msp *msp) validateTLSCACertificate(cert *x509.Certificate, opts x509.VerifyOptions) error {
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

func (msp *msp) validateCertAgainstChain(cert *x509.Certificate, validationChain []*x509.Certificate) error {
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

func (msp *msp) setupCrypto(conf *pmsp.MayyMSPConfig) error {
	msp.cryptoConfig = conf.CryptoConfig
	if msp.cryptoConfig == nil {
		msp.cryptoConfig = &pmsp.MayyCryptoConfig{
			SignatureHashFamily:            hash.SHA3_256,
			IdentityIdentifierHashFunction: hash.SHA256,
		}
	}
	if msp.cryptoConfig.SignatureHashFamily == "" {
		msp.cryptoConfig.SignatureHashFamily = hash.SHA3_256
	}
	if msp.cryptoConfig.IdentityIdentifierHashFunction == "" {
		msp.cryptoConfig.IdentityIdentifierHashFunction = hash.SHA256
	}

	return nil
}

func (msp *msp) setupCAs(conf *pmsp.MayyMSPConfig) error {
	if len(conf.RootCerts) == 0 {
		return errors.NewError("expected at least one ca certificate")
	}

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
		id, _, err := msp.getIdentityFromCert(rootCert)
		if err != nil {
			return errors.NewErrorf("failed adding root ca certificate, the error is \"%s\"", err.Error())
		}
		msp.rootCerts = append(msp.rootCerts, id)
	}
	for _, intermediateCert := range conf.IntermediateCerts {
		id, _, err := msp.getIdentityFromCert(intermediateCert)
		if err != nil {
			return errors.NewErrorf("failed adding intermediate ca certificate, the error is \"%s\"", err.Error())
		}
		msp.intermediateCerts = append(msp.intermediateCerts, id)
	}

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

func (msp *msp) finalizeSetupCAs() error {
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

func (msp *msp) setupAdmins(conf *pmsp.MayyMSPConfig) error {
	return msp.internalSetupAdmins(conf)
}

func (msp *msp) setupAdminsV1_0(conf *pmsp.MayyMSPConfig) error {
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

func (msp *msp) setupCRLs(conf *pmsp.MayyMSPConfig) error {
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

/* ------------------------------------------------------------------------------------------ */
// utils

func (msp *msp) getValidityOptsForCert(cert *x509.Certificate) x509.VerifyOptions {
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
func (msp *msp) getCertifiersIdentifier(certRaw []byte) ([]byte, error) {
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
		chain, err = msp.getValidationChain(cert, true)
		if err != nil {
			return nil, err
		}
	}

	return msp.getCertificationChainIdentifierFromChain(chain)
}

func (msp *msp) getCertificationChainIdentifier(id Identity) ([]byte, error) {
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

func (msp *msp) getCertificationChainIdentifierFromChain(chain []*x509.Certificate) ([]byte, error) {
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

func (msp *msp) getCertFromPem(idBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(idBytes)
	return x509.ParseCertificate(block.Bytes)
}

func (msp *msp) getIdentityFromCert(certBytes []byte) (Identity, csp.Key, error) {
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

func (msp *msp) isInAdmins(id *identity) bool {
	for _, admin := range msp.admins {
		if bytes.Equal(id.cert.Raw, admin.(*identity).cert.Raw) {
			return true
		}
	}
	return false
}

func (msp *msp) deserializeIdentityInternal(certBytes []byte) (Identity, error) {
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
