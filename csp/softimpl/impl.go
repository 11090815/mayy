package softimpl

import (
	"hash"
	"reflect"

	"github.com/11090815/mayy/csp"
	"github.com/11090815/mayy/errors"
)

/* ------------------------------------------------------------------------------------------ */

type SoftCSPImpl struct {
	keyStore csp.KeyStore

	KeyGenerators map[reflect.Type]csp.KeyGenerator
	KeyDerivers   map[reflect.Type]csp.KeyDeriver
	KeyImporters  map[reflect.Type]csp.KeyImporter
	Encrypters    map[reflect.Type]csp.Encrypter
	Decrypters    map[reflect.Type]csp.Decrypter
	Signers       map[reflect.Type]csp.Signer
	Verifiers     map[reflect.Type]csp.Verifier
	Hashers       map[reflect.Type]csp.Hasher
	CAGenerators  map[reflect.Type]csp.CAGenerator
}

func NewSoftCSPImpl(ks csp.KeyStore) (csp.CSP, error) {
	if ks == nil {
		return nil, errors.NewError("invalid key store, nil key store")
	}

	impl := &SoftCSPImpl{
		keyStore:      ks,
		KeyGenerators: make(map[reflect.Type]csp.KeyGenerator),
		KeyDerivers:   make(map[reflect.Type]csp.KeyDeriver),
		KeyImporters:  make(map[reflect.Type]csp.KeyImporter),
		Encrypters:    make(map[reflect.Type]csp.Encrypter),
		Decrypters:    make(map[reflect.Type]csp.Decrypter),
		Signers:       make(map[reflect.Type]csp.Signer),
		Verifiers:     make(map[reflect.Type]csp.Verifier),
		Hashers:       make(map[reflect.Type]csp.Hasher),
		CAGenerators:  make(map[reflect.Type]csp.CAGenerator),
	}

	return impl, nil
}

func (csp *SoftCSPImpl) KeyGen(opts csp.KeyGenOpts) (csp.Key, error) {
	if opts == nil {
		return nil, errors.NewError("invalid option, nil option")
	}

	kg, found := csp.KeyGenerators[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.NewErrorf("cannot find out the key generator for the option \"%T\"", opts)
	}

	key, err := kg.KeyGen(opts)
	if err != nil {
		return nil, errors.NewErrorf("failed generating key with option \"%T\", the error is \"%s\"", opts, err.Error())
	}

	if !opts.Ephemeral() {
		return key, csp.keyStore.StoreKey(key)
	}

	return key, nil
}

func (csp *SoftCSPImpl) KeyDeriv(key csp.Key, opts csp.KeyDerivOpts) (csp.Key, error) {
	if key == nil {
		return nil, errors.NewError("invalid key, nil key")
	}

	if opts == nil {
		return nil, errors.NewError("invalid option, nil option")
	}

	kd, found := csp.KeyDerivers[reflect.TypeOf(key)]
	if !found {
		return nil, errors.NewErrorf("cannot find out the key deriver for the key of type \"%T\"", key)
	}

	dk, err := kd.KeyDeriv(key, opts)
	if err != nil {
		return nil, errors.NewErrorf("failed deriving key with option \"%T\", the error is \"%s\"", opts, err.Error())
	}

	if !opts.Ephemeral() {
		return dk, csp.keyStore.StoreKey(dk)
	}

	return dk, nil
}

func (csp *SoftCSPImpl) KeyImport(raw interface{}, opts csp.KeyImportOpts) (csp.Key, error) {
	if raw == nil {
		return nil, errors.NewError("invalid raw material, nil raw material")
	}
	if opts == nil {
		return nil, errors.NewError("invalid option, nil option")
	}

	ki, found := csp.KeyImporters[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.NewErrorf("cannot find out the key importer for the option \"%T\"", opts)
	}

	key, err := ki.KeyImport(raw, opts)
	if err != nil {
		return nil, errors.NewErrorf("failed importing key with option \"%T\", the error is \"%s\"", opts, err.Error())
	}

	if !opts.Ephemeral() {
		return key, csp.keyStore.StoreKey(key)
	}

	return key, nil
}

func (csp *SoftCSPImpl) GetKey(ski []byte) (csp.Key, error) {
	return csp.keyStore.GetKey(ski)
}

func (csp *SoftCSPImpl) Hash(msg []byte, opts csp.HashOpts) ([]byte, error) {
	if opts == nil {
		return nil, errors.NewError("invalid option, nil option")
	}

	hasher, found := csp.Hashers[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.NewErrorf("cannot find out the hash function for the option \"%T\"", opts)
	}

	digest, err := hasher.Hash(msg, opts)
	if err != nil {
		return nil, errors.NewErrorf("failed hashing message with option \"%T\"", opts)
	}

	return digest, nil
}

func (csp *SoftCSPImpl) GetHash(opts csp.HashOpts) (hash.Hash, error) {
	if opts == nil {
		return nil, errors.NewError("invalid option, nil option")
	}

	hasher, found := csp.Hashers[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.NewErrorf("cannot find out the hash function for the option \"%T\"", opts)
	}

	hf, err := hasher.GetHash(opts)
	if err != nil {
		return nil, errors.NewErrorf("failed get hash function with option \"%T\"", opts)
	}

	return hf, nil
}

func (csp *SoftCSPImpl) Sign(key csp.Key, digest []byte, opts csp.SignerOpts) ([]byte, error) {
	if key == nil {
		return nil, errors.NewErrorf("invalid key, nil key")
	}

	if len(digest) == 0 {
		return nil, errors.NewError("invalid digest, nil digest")
	}

	signer, found := csp.Signers[reflect.TypeOf(key)]
	if !found {
		return nil, errors.NewErrorf("cannot find out the signer for the key \"%T\"", key)
	}

	return signer.Sign(key, digest, opts)
}

func (csp *SoftCSPImpl) Verify(key csp.Key, sig, digest []byte, opts csp.SignerOpts) (bool, error) {
	if key == nil {
		return false, errors.NewErrorf("invalid key, nil key")
	}

	if len(digest) == 0 {
		return false, errors.NewError("invalid digest, nil digest")
	}

	if len(sig) == 0 {
		return false, errors.NewError("invalid signature, nil signatire")
	}

	verifier, found := csp.Verifiers[reflect.TypeOf(key)]
	if !found {
		return false, errors.NewErrorf("cannot find out the verifier for the key \"%T\"", key)
	}

	return verifier.Verify(key, sig, digest, opts)
}

func (csp *SoftCSPImpl) Encrypt(key csp.Key, plaintext []byte, opts csp.EncrypterOpts) ([]byte, error) {
	if key == nil {
		return nil, errors.NewErrorf("invalid key, nil key")
	}

	encrypter, found := csp.Encrypters[reflect.TypeOf(key)]
	if !found {
		return nil, errors.NewErrorf("cannot find out the encrypter for the key \"%T\"", key)
	}

	return encrypter.Encrypt(key, plaintext, opts)
}

func (csp *SoftCSPImpl) Decrypt(key csp.Key, ciphertext []byte, opts csp.DecrypterOpts) ([]byte, error) {
	if key == nil {
		return nil, errors.NewErrorf("invalid key, nil key")
	}

	decrypter, found := csp.Decrypters[reflect.TypeOf(key)]
	if !found {
		return nil, errors.NewErrorf("cannot find out the decrypter for the key \"%T\"", key)
	}

	return decrypter.Decrypt(key, ciphertext, opts)
}

func (csp *SoftCSPImpl) CAGen(opts csp.CAGenOpts) (csp.CA, error) {
	if opts == nil {
		return nil, errors.NewError("invalid opts, nil opts")
	}

	cg, found := csp.CAGenerators[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.NewErrorf("cannot find out the CA generator for the opts of type \"%T\"", opts)

	}
	return cg.GenCA(opts)
}

func RegisterWidget(scsp *SoftCSPImpl, t reflect.Type, w interface{}) error {
	if t == nil {
		return errors.NewError("invalid type, nil type")
	}

	if w == nil {
		return errors.NewError("invalid widget, nil widget")
	}

	switch ww := w.(type) {
	case csp.KeyGenerator:
		scsp.KeyGenerators[t] = ww
	case csp.KeyImporter:
		scsp.KeyImporters[t] = ww
	case csp.KeyDeriver:
		scsp.KeyDerivers[t] = ww
	case csp.Signer:
		scsp.Signers[t] = ww
	case csp.Verifier:
		scsp.Verifiers[t] = ww
	case csp.Encrypter:
		scsp.Encrypters[t] = ww
	case csp.Decrypter:
		scsp.Decrypters[t] = ww
	case csp.Hasher:
		scsp.Hashers[t] = ww
	case csp.CAGenerator:
		scsp.CAGenerators[t] = ww
	default:
		return errors.NewErrorf("widget type \"%T\" is not recognized", w)
	}
	return nil
}
