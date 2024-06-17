package msp

import (
	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/protobuf/pmsp"
	"google.golang.org/protobuf/proto"
)

type mspManagerImpl struct {
	msps            map[string]MSP
	mspsByProviders map[ProviderType][]MSP
	isRunning       bool
}

func NewMSPManager() MSPManager {
	return &mspManagerImpl{}
}

func (manager *mspManagerImpl) Setup(msps []MSP) error {
	if manager.isRunning {
		mspLogger.Info("MSP Manager is already running.")
		return nil
	}

	mspLogger.Debugf("Setting up the MSP Manager with %d msps.", len(msps))
	manager.msps = make(map[string]MSP)
	manager.mspsByProviders = make(map[ProviderType][]MSP)

	for _, msp := range msps {
		manager.msps[msp.GetIdentifier()] = msp
		manager.mspsByProviders[msp.GetType()] = append(manager.mspsByProviders[msp.GetType()], msp)
	}
	manager.isRunning = true

	return nil
}

func (manager *mspManagerImpl) GetMSPs() map[string]MSP {
	return manager.msps
}

func (manager *mspManagerImpl) DeserializeIdentity(serializedID []byte) (Identity, error) {
	if !manager.isRunning {
		return nil, errors.NewError("msp manager is not running")
	}
	sid := &pmsp.SerializedIdentity{}
	if err := proto.Unmarshal(serializedID, sid); err != nil {
		return nil, err
	}
	if manager.msps[sid.Mspid] == nil {
		return nil, errors.NewErrorf("msp %s is not exists", sid.Mspid)
	}

	return manager.msps[sid.Mspid].DeserializeIdentity(serializedID)
}

func (manager *mspManagerImpl) IsWellFormed(sid *pmsp.SerializedIdentity) error {
	for _, msps := range manager.mspsByProviders {
		if err := msps[0].IsWellFormed(sid); err == nil {
			return nil
		}
	}
	return errors.NewError("no msp provider recognizes the identity")
}
