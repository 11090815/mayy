package interfaces

import "hash"

/* ------------------------------------------------------------------------------------------ */

type KeyGenerator interface {
	KeyGen(opts KeyGenOpts) (Key, error)
}

type KeyDeriver interface {
	KeyDeriv(key Key, opts KeyDerivOpts) (Key, error)
}

type KeyImporter interface {
	KeyImport(raw interface{}, opts KeyImportOpts) (Key, error)
}

/* ------------------------------------------------------------------------------------------ */

type Encrypter interface {
	Encrypt(key Key, plaintext []byte, opts EncrypterOpts) ([]byte, error)
}

type Decrypter interface {
	Decrypt(key Key, ciphertext []byte, opts DecrypterOpts) ([]byte, error)
}

/* ------------------------------------------------------------------------------------------ */

type Signer interface {
	Sign(key Key, digest []byte, opts SignerOpts) ([]byte, error)
}

type Verifier interface {
	Verify(key Key, signature, digest []byte, opts SignerOpts) (bool, error)
}

/* ------------------------------------------------------------------------------------------ */

type Hasher interface {
	Hash(msg []byte, opts HashOpts) ([]byte, error)
	GetHash(opts HashOpts) (hash.Hash, error)
}

/* ------------------------------------------------------------------------------------------ */

type CAGenerator interface {
	CAGen(opts CAGenOpts) (CA, error)
}
