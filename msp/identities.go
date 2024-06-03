package msp

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"sync"
	"time"

	"github.com/11090815/mayy/csp"
	"github.com/11090815/mayy/csp/softimpl/hash"
	"github.com/11090815/mayy/errors"
	"github.com/11090815/mayy/protobuf/pmsp"
	"google.golang.org/protobuf/proto"
)

type identity struct {
	// identityIdentifier 简单的表示身份的身份标识符。
	identityIdentifier *IdentityIdentifier

	// cert 此身份的 x509 证书。
	cert *x509.Certificate

	// publicKey 此身份的公钥。
	publicKey csp.Key

	// msp 是一个索引，该 msp 管理此身份。
	msp *mspImpl

	validationMutex sync.Mutex

	validated bool

	validationErr error
}

func newIdentity(cert *x509.Certificate, pk csp.Key, msp *mspImpl) (id Identity, err error) {
	cert, err = msp.sanitizeCert(cert)
	if err != nil {
		return nil, err
	}

	hashOpt, err := hash.GetHashOpt(msp.cryptoConfig.IdentityIdentifierHashFunction)
	if err != nil {
		return nil, err
	}

	digest, err := msp.csp.Hash(cert.Raw, hashOpt)
	if err != nil {
		return nil, err
	}

	identityIdentifier := &IdentityIdentifier{
		Mspid: msp.identifier,
		Id:    hex.EncodeToString(digest),
	}
	return &identity{identityIdentifier: identityIdentifier, cert: cert, publicKey: pk, msp: msp}, nil
}

func (id *identity) ExpiresAt() time.Time {
	return id.cert.NotAfter
}

func (id *identity) GetIdentifier() *IdentityIdentifier {
	return id.identityIdentifier
}

func (id *identity) GetMSPIdentifier() string {
	return id.identityIdentifier.Mspid
}

func (id *identity) Validate() error {
	return id.msp.Validate(id)
}

func (id *identity) GetOrganizationalUnits() []*OUIdentifier {
	if id.cert == nil {
		return nil
	}

	cid, err := id.msp.getCertificationChainIdentifier(id)
	if err != nil {
		mspLogger.Errorf("Failed getting organizational units, because %s.", err.Error())
		return nil
	}

	var ouis []*OUIdentifier
	for _, ou := range id.cert.Subject.OrganizationalUnit {
		ouis = append(ouis, &OUIdentifier{
			OrganizationalUnitIdentifier: ou,
			CertifiersIdentifier:         cid,
		})
	}

	return ouis
}

// Anonymous 对于 identity 来说，它不可能是匿名的。
func (id *identity) Anonymous() bool {
	return false
}

func (id *identity) Verify(msg []byte, signature []byte) error {
	hashOpt, err := hash.GetHashOpt(id.msp.cryptoConfig.SignatureHashFunction)
	if err != nil {
		return errors.NewErrorf("failed verifying the signature, the error is \"%s\"", err.Error())
	}
	digest, err := id.msp.csp.Hash(msg, hashOpt)
	if err != nil {
		return errors.NewErrorf("failed verifying the signature, the error is \"%s\"", err.Error())
	}
	valid, err := id.msp.csp.Verify(id.publicKey, signature, digest, nil)
	if err != nil {
		return errors.NewErrorf("failed verifying the signature, the error is \"%s\"", err.Error())
	} else if !valid {
		return errors.NewError("invalid signature")
	}

	return nil
}

func (id *identity) Serialize() ([]byte, error) {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: id.cert.Raw}
	certBytes := pem.EncodeToMemory(block)
	sid := &pmsp.SerializedIdentity{
		Mspid:   id.msp.identifier,
		IdBytes: certBytes,
	}

	return proto.Marshal(sid)
}

func (id *identity) SatisfiesPrinciple(principal *pmsp.MSPPrinciple) error {
	return id.msp.SatisfiesPrinciple(id, principal)
}

/* ------------------------------------------------------------------------------------------ */

type signingIdentity struct {
	identity
	signer crypto.Signer
}

func newSigningIdentity(cert *x509.Certificate, pk csp.Key, signer crypto.Signer, msp *mspImpl) (SigningIdentity, error) {
	id, err := newIdentity(cert, pk, msp)
	if err != nil {
		return nil, err
	}

	return &signingIdentity{
		identity: identity{
			identityIdentifier: id.(*identity).identityIdentifier,
			cert:               id.(*identity).cert,
			msp:                msp,
			publicKey:          pk,
		},
		signer: signer,
	}, nil
}

func (sid *signingIdentity) Sign(msg []byte) ([]byte, error) {
	hashOpt, err := hash.GetHashOpt(sid.msp.cryptoConfig.SignatureHashFunction)
	if err != nil {
		return nil, err
	}

	digest, err := sid.msp.csp.Hash(msg, hashOpt)
	if err != nil {
		return nil, err
	}

	return sid.signer.Sign(rand.Reader, digest, nil)
}

// GetPublicVersion 即返回 signingIdentity.identity。
func (sid *signingIdentity) GetPublicVersion() Identity {
	return &sid.identity
}
