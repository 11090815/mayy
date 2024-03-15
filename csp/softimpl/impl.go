package softimpl

import (
	"hash"
	"reflect"

	"github.com/11090815/mayy/csp/interfaces"
	"github.com/11090815/mayy/errors"
)

/* ------------------------------------------------------------------------------------------ */

type SoftCSPImpl struct {
	keyStore interfaces.KeyStore

	KeyGenerators map[reflect.Type]interfaces.KeyGenerator
	KeyDerivers   map[reflect.Type]interfaces.KeyDeriver
	KeyImporters  map[reflect.Type]interfaces.KeyImporter
	Encrypters    map[reflect.Type]interfaces.Encrypter
	Decrypters    map[reflect.Type]interfaces.Decrypter
	Signers       map[reflect.Type]interfaces.Signer
	Verifiers     map[reflect.Type]interfaces.Verifier
	Hashers       map[reflect.Type]interfaces.Hasher
}

func NewSoftCSPImpl(ks interfaces.KeyStore) (interfaces.CSP, error) {
	if ks == nil {
		return nil, errors.NewError("invalid key store, nil key store")
	}

	impl := &SoftCSPImpl{
		keyStore:      ks,
		KeyGenerators: make(map[reflect.Type]interfaces.KeyGenerator),
		KeyDerivers:   make(map[reflect.Type]interfaces.KeyDeriver),
		KeyImporters:  make(map[reflect.Type]interfaces.KeyImporter),
		Encrypters:    make(map[reflect.Type]interfaces.Encrypter),
		Decrypters:    make(map[reflect.Type]interfaces.Decrypter),
		Signers:       make(map[reflect.Type]interfaces.Signer),
		Verifiers:     make(map[reflect.Type]interfaces.Verifier),
		Hashers:       make(map[reflect.Type]interfaces.Hasher),
	}

	return impl, nil
}

func (csp *SoftCSPImpl) KeyGen(opts interfaces.KeyGenOpts) (interfaces.Key, error) {
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

func (csp *SoftCSPImpl) KeyDeriv(key interfaces.Key, opts interfaces.KeyDerivOpts) (interfaces.Key, error) {
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

func (csp *SoftCSPImpl) KeyImport(raw interface{}, opts interfaces.KeyImportOpts) (interfaces.Key, error) {
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

func (csp *SoftCSPImpl) GetKey(ski []byte) (interfaces.Key, error) {
	return csp.keyStore.GetKey(ski)
}

func (csp *SoftCSPImpl) Hash(msg []byte, opts interfaces.HashOpts) ([]byte, error) {
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

func (csp *SoftCSPImpl) GetHash(opts interfaces.HashOpts) (hash.Hash, error) {
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

func (csp *SoftCSPImpl) Sign(key interfaces.Key, digest []byte, opts interfaces.SignerOpts) ([]byte, error) {
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

func (csp *SoftCSPImpl) Verify(key interfaces.Key, sig, digest []byte, opts interfaces.SignerOpts) (bool, error) {
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

func (csp *SoftCSPImpl) Encrypt(key interfaces.Key, plaintext []byte, opts interfaces.EncrypterOpts) ([]byte, error) {
	if key == nil {
		return nil, errors.NewErrorf("invalid key, nil key")
	}

	encrypter, found := csp.Encrypters[reflect.TypeOf(key)]
	if !found {
		return nil, errors.NewErrorf("cannot find out the encrypter for the key \"%T\"", key)
	}

	return encrypter.Encrypt(key, plaintext, opts)
}

func (csp *SoftCSPImpl) Decrypt(key interfaces.Key, ciphertext []byte, opts interfaces.DecrypterOpts) ([]byte, error) {
	if key == nil {
		return nil, errors.NewErrorf("invalid key, nil key")
	}

	decrypter, found := csp.Decrypters[reflect.TypeOf(key)]
	if !found {
		return nil, errors.NewErrorf("cannot find out the decrypter for the key \"%T\"", key)
	}

	return decrypter.Decrypt(key, ciphertext, opts)
}

func RegisterWidget(csp *SoftCSPImpl, t reflect.Type, w interface{}) error {
	if t == nil {
		return errors.NewError("invalid type, nil type")
	}

	if w == nil {
		return errors.NewError("invalid widget, nil widget")
	}

	switch ww := w.(type) {
	case interfaces.KeyGenerator:
		csp.KeyGenerators[t] = ww
	case interfaces.KeyImporter:
		csp.KeyImporters[t] = ww
	case interfaces.KeyDeriver:
		csp.KeyDerivers[t] = ww
	case interfaces.Signer:
		csp.Signers[t] = ww
	case interfaces.Verifier:
		csp.Verifiers[t] = ww
	case interfaces.Encrypter:
		csp.Encrypters[t] = ww
	case interfaces.Decrypter:
		csp.Decrypters[t] = ww
	case interfaces.Hasher:
		csp.Hashers[t] = ww
	default:
		return errors.NewErrorf("widget type \"%T\" is not recognized", w)
	}
	return nil
}
