package msp

import (
	"encoding/pem"
	"os"
	"path/filepath"

	"github.com/11090815/mayy/csp/factory"
	"github.com/11090815/mayy/csp/softimpl/hash"
	"github.com/11090815/mayy/errors"
	"github.com/11090815/mayy/protobuf/pmsp"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

const (
	cacerts              = "cacerts"
	admincerts           = "admincerts"
	signcerts            = "signcerts"
	keystore             = "keystore"
	intermediatecerts    = "intermediatecerts"
	crlsfolder           = "crls"
	configfilename       = "config.yaml"
	tlscacerts           = "tlscacerts"
	tlsintermediatecerts = "tlsintermediatecerts"
)

/* ------------------------------------------------------------------------------------------ */

type OrganizationalUnitIdentifiersConfiguration struct {
	// Certificate 表示根证书或中级证书的存放路径。
	Certificate string `yaml:"Certificate,omitempty"`
	// OrganizationalUnitIdentifier 表示组织单元的名字。
	OrganizationalUnitIdentifier string `yaml:"OrganizationalUnitIdentifier,omitempty"`
}

// NodeOUs 包含关于如何根据 OUs 区分客户端、对等端和订购方的信息。如果通过将 Enabled 设置为 true 强制执行该检查，则 MSP 将认为一
// 个身份是有效的，如果它是客户端、peer 端或 orderer 的身份。一个身份标识应该只有这些特殊 OUs 中的一个。
type NodeOUs struct {
	Enable bool `yaml:"Enable,omitempty"`
	// ClientOUIdentifier 规定了如何根据 OU 识别 clients。
	ClientOUIdentifier *OrganizationalUnitIdentifiersConfiguration `yaml:"ClientOUIdentifier,omitempty"`
	// PeerOUIdentifier 规定了如何根据 OU 识别 peers。
	PeerOUIdentifier *OrganizationalUnitIdentifiersConfiguration `yaml:"PeerOUIdentifier,omitempty"`
	// AdminOUIdentifier 规定了如何根据 OU 识别 admins。
	AdminOUIdentifier *OrganizationalUnitIdentifiersConfiguration `yaml:"AdminOUIdentifier,omitempty"`
	// OrdererOUIdentifier 规定了如何根据 OU 识别 orderers。
	OrdererOUIdentifier *OrganizationalUnitIdentifiersConfiguration `yaml:"OrdererOUIdentifier,omitempty"`
}

// Configuration 表示 MSP 可以配备的附件配置。默认情况下，此配置存储在一个 yaml 文件中
type Configuration struct {
	// OrganizationalUnitIdentifiers 是 OUs 列表。如果设置了此值，则 MSP 将认为只有包含这些 OUs 中的至少一个的标识才是有效的。
	OrganizationalUnitIdentifiers []*OrganizationalUnitIdentifiersConfiguration `yaml:"OrganizationalUnitIdentifiers,omitempty"`
	// NodeOUs 使 MSP 能够根据身份的 OU 区分 clients、peers 和 orderers。
	NodeOUs *NodeOUs `yaml:"NodeOUs,omitempty"`
}

func readFile(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.NewError(err.Error())
	}
	return content, nil
}

func readPemFile(path string) ([]byte, error) {
	bz, err := readFile(path)
	if err != nil {
		return nil, errors.NewError(err.Error())
	}

	block, _ := pem.Decode(bz)
	if block == nil {
		return nil, errors.NewErrorf("no pem content for file %s", path)
	}

	return bz, nil
}

func getPemMaterialFromDir(dir string) ([][]byte, error) {
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return nil, err
	}

	content := make([][]byte, 0)
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		fullpath := filepath.Join(dir, file.Name())
		stat, err := os.Stat(fullpath)
		if err != nil {
			continue
		}
		if stat.IsDir() {
			continue
		}
		item, err := readPemFile(fullpath)
		if err != nil {
			continue
		}
		content = append(content, item)
	}

	return content, nil
}

func SetupCSPKeystoreConfig(cfg *factory.FactoryOpts, keystoreDir string) *factory.FactoryOpts {
	var err error
	if cfg == nil {
		cfg, err = factory.ReadConfig()
		if err != nil {
			panic(err)
		}
	}

	cfg.KeyStorePath = keystoreDir

	return cfg
}

// GetLocalMspConfigWithType 方法的第四个参数目前仅支持 "csp"。
func GetLocalMspConfigWithType(dir string, cfg *factory.FactoryOpts, id, mspType string) (*pmsp.MSPConfig, error) {
	switch mspType {
	case ProviderTypeToString(CSP):
		return GetLocalMspConfig(dir, cfg, id)
	default:
		return nil, errors.NewErrorf("unknown MSP type \"%s\"", mspType)
	}
}

func GetLocalMspConfig(dir string, cfg *factory.FactoryOpts, id string) (*pmsp.MSPConfig, error) {
	signcertDir := filepath.Join(dir, signcerts)
	keystoreDir := filepath.Join(dir, keystore)
	cfg = SetupCSPKeystoreConfig(cfg, keystoreDir)
	factory.InitCSPFactoryWithOpts(cfg)

	signCert, err := getPemMaterialFromDir(signcertDir)
	if err != nil || len(signCert) == 0 {
		return nil, errors.NewErrorf("failed loading a valid signer certificate from directory %s", signcertDir)
	}

	sigid := &pmsp.SigningIdentityInfo{PublicSigner: signCert[0], PrivateSigner: nil}

	return getMspConfig(dir, id, sigid)
}

// GetVerifyingMspConfig 方法的第三个参数目前仅支持 "csp"。
func GetVerifyingMspConfig(dir, id, mspType string) (*pmsp.MSPConfig, error) {
	switch mspType {
	case ProviderTypeToString(CSP):
		return getMspConfig(dir, id, nil)
	default:
		return nil, errors.NewErrorf("unknown msp type: \"%s\"", mspType)
	}
}

func getMspConfig(dir, id string, sigid *pmsp.SigningIdentityInfo) (*pmsp.MSPConfig, error) {
	// CA 证书的存放路径
	cacertsDir := filepath.Join(dir, cacerts)
	// 管理员的证书的存放路径
	admincertsDir := filepath.Join(dir, admincerts)
	// 中级 CA 的证书存放路径
	intermediatecertsDir := filepath.Join(dir, intermediatecerts)
	// 撤销证书的存放路径
	crlsDir := filepath.Join(dir, crlsfolder)
	// 配置文件的存放路径
	configFile := filepath.Join(dir, configfilename)
	// CA 的 TLS 证书存放路径
	tlscacertsDir := filepath.Join(dir, tlscacerts)
	// 中级 CA 的 TLS 证书存放路径
	tlsintermediatecertsDir := filepath.Join(dir, tlsintermediatecerts)

	cacertsMaterial, err := getPemMaterialFromDir(cacertsDir)
	if err != nil || len(cacertsMaterial) == 0 {
		return nil, errors.NewErrorf("failed loading ca certificates from directory %s", cacertsDir)
	}

	admincertsMaterial, err := getPemMaterialFromDir(admincertsDir)
	if err != nil || len(admincertsMaterial) == 0 {
		return nil, errors.NewErrorf("failed loading admin certificates from directory %s", admincertsDir)
	}

	intermediatecertsMaterial, err := getPemMaterialFromDir(intermediatecertsDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.NewErrorf("failed loading intermediate certificates from directory %s", intermediatecertsDir)
	}

	tlsCACertsMaterial, err := getPemMaterialFromDir(tlscacertsDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.NewErrorf("failed loading tls ca certificates from directory %s", tlscacertsDir)
	}

	tlsintermediatecertsMaterial, err := getPemMaterialFromDir(tlsintermediatecertsDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.NewErrorf("failed loading tls intermediate certificates from directory %s", tlsintermediatecertsDir)
	}

	crlsMaterial, err := getPemMaterialFromDir(crlsDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.NewErrorf("failed loading crls from directory %s", crlsDir)
	}

	var ouis []*pmsp.MayyOUIdentifier
	var nodeOUs *pmsp.MayyNodeOUs
	_, err = os.Stat(configFile)
	if err == nil {
		raw, err := os.ReadFile(configFile)
		if err != nil {
			return nil, errors.NewErrorf("failed loading configuration file: \"%s\"", err.Error())
		}

		configuration := Configuration{}
		if err = yaml.Unmarshal(raw, &configuration); err != nil {
			return nil, errors.NewErrorf("failed unmarshaling configuration: \"%s\"", err.Error())
		}

		// OrganizationalUnitIdentifiers
		if len(configuration.OrganizationalUnitIdentifiers) > 0 {
			for _, ouID := range configuration.OrganizationalUnitIdentifiers {
				certRaw, err := readFile(filepath.Join(dir, ouID.Certificate))
				if err != nil {
					return nil, errors.NewErrorf("failed loading organizational unit certificate: \"%s\"", err.Error())
				}

				mouid := &pmsp.MayyOUIdentifier{
					Certificate:                certRaw,
					OrganizationUnitIdentifier: ouID.OrganizationalUnitIdentifier,
				}

				ouis = append(ouis, mouid)
			}
		}

		// NodeOUs & Certificate
		if configuration.NodeOUs != nil && configuration.NodeOUs.Enable {
			nodeOUs = &pmsp.MayyNodeOUs{
				Enable: true,
			}
			if configuration.NodeOUs.ClientOUIdentifier != nil && configuration.NodeOUs.ClientOUIdentifier.OrganizationalUnitIdentifier != "" {
				nodeOUs.ClientOuIdentifier = &pmsp.MayyOUIdentifier{OrganizationUnitIdentifier: configuration.NodeOUs.ClientOUIdentifier.OrganizationalUnitIdentifier}
				nodeOUs.ClientOuIdentifier.Certificate = loadCertificateAt(dir, configuration.NodeOUs.ClientOUIdentifier.Certificate)
			}
			if configuration.NodeOUs.PeerOUIdentifier != nil && configuration.NodeOUs.PeerOUIdentifier.OrganizationalUnitIdentifier != "" {
				nodeOUs.PeerOuIdentifier = &pmsp.MayyOUIdentifier{OrganizationUnitIdentifier: configuration.NodeOUs.ClientOUIdentifier.OrganizationalUnitIdentifier}
				nodeOUs.PeerOuIdentifier.Certificate = loadCertificateAt(dir, configuration.NodeOUs.PeerOUIdentifier.Certificate)
			}
			if configuration.NodeOUs.AdminOUIdentifier != nil && configuration.NodeOUs.AdminOUIdentifier.OrganizationalUnitIdentifier != "" {
				nodeOUs.AdminOuIdentifier = &pmsp.MayyOUIdentifier{OrganizationUnitIdentifier: configuration.NodeOUs.AdminOUIdentifier.OrganizationalUnitIdentifier}
				nodeOUs.AdminOuIdentifier.Certificate = loadCertificateAt(dir, configuration.NodeOUs.AdminOUIdentifier.Certificate)
			}
			if configuration.NodeOUs.OrdererOUIdentifier != nil && configuration.NodeOUs.OrdererOUIdentifier.OrganizationalUnitIdentifier != "" {
				nodeOUs.OrdererOuIdentifier = &pmsp.MayyOUIdentifier{OrganizationUnitIdentifier: configuration.NodeOUs.OrdererOUIdentifier.OrganizationalUnitIdentifier}
				nodeOUs.OrdererOuIdentifier.Certificate = loadCertificateAt(dir, configuration.NodeOUs.OrdererOUIdentifier.Certificate)
			}
		}
	}

	cryptoConfig := &pmsp.MayyCryptoConfig{
		SignatureHashFunction:          hash.SHA256,
		IdentityIdentifierHashFunction: hash.SHA256,
	}

	mmspConfig := &pmsp.MayyMSPConfig{
		Admins:                      admincertsMaterial,
		RootCerts:                   cacertsMaterial,
		IntermediateCerts:           intermediatecertsMaterial,
		SigningIdentity:             sigid,
		Name:                        id,
		OrganizationUnitIdentifiers: ouis,
		RevocationList:              crlsMaterial,
		CryptoConfig:                cryptoConfig,
		TlsRootCerts:                tlsCACertsMaterial,
		TlsIntermediateCerts:        tlsintermediatecertsMaterial,
		MayyNodeOus:                 nodeOUs,
	}

	raw, err := proto.Marshal(mmspConfig)
	if err != nil {
		return nil, err
	}

	return &pmsp.MSPConfig{Config: raw, Type: int32(CSP)}, nil
}

func loadCertificateAt(dir, certificatePath string) []byte {
	if certificatePath == "" {
		return nil
	}

	fullpath := filepath.Join(dir, certificatePath)
	raw, err := readFile(fullpath)
	if err != nil {
		return nil
	} else {
		return raw
	}
}
