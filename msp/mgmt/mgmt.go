package mgmt

import (
	"sync"

	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/csp"
	"github.com/11090815/mayy/msp"
	"github.com/spf13/viper"
)

var (
	mspLogger     = mlog.GetLogger("msp", mlog.DebugLevel, true)
	mutex         sync.Mutex
	localMsp      msp.MSP
	mspManagerMap = make(map[string]msp.MSPManager)
)

func GetDeserializers() map[string]msp.IdentityDeserializer {
	mutex.Lock()
	defer mutex.Unlock()

	clone := make(map[string]msp.IdentityDeserializer)

	for key, manager := range mspManagerMap {
		clone[key] = manager
	}

	return clone
}

func GetIdentityDeserializer(chainID string, cryptoProvider csp.CSP) msp.IdentityDeserializer {
	if chainID == "" {
		return GetLocalMSP(cryptoProvider)
	}

	return GetManagerForChain(chainID)
}

func SetMSPManager(chainID string, manager msp.MSPManager) {
	mutex.Lock()
	defer mutex.Unlock()
	mspManagerMap[chainID] = manager
}

func GetManagerForChain(chainID string) msp.MSPManager {
	mutex.Lock()
	defer mutex.Unlock()

	manager, ok := mspManagerMap[chainID]
	if !ok {
		mspLogger.Debugf("Created a new msp manager for channel \"%s\"", chainID)
		manager = msp.NewMSPManager()
		mspManagerMap[chainID] = manager
	}

	return manager
}

func GetLocalMSP(csp csp.CSP) msp.MSP {
	mutex.Lock()
	defer mutex.Unlock()

	if localMsp != nil {
		return localMsp
	}

	localMsp = loadLocalMSP(csp)

	return localMsp
}

func loadLocalMSP(csp csp.CSP) msp.MSP {
	mspType := viper.GetString("peer.localMspType")
	if mspType == "" {
		mspType = msp.ProviderTypeToString(msp.CSP)
	}

	newOpts, found := msp.Options[mspType]
	if !found {
		mspLogger.Panicf("msp type %s is not recognized", mspType)
	}

	mspInst, err := msp.NewMSP(newOpts, csp)
	if err != nil {
		mspLogger.Panicf("Failed to initialize local msp, the error is \"%s\"", err.Error())
	}

	mspLogger.Debugf("Created new local msp %s.", mspInst.GetIdentifier())

	return mspInst
}
