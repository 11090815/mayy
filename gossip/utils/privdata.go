package utils

import (
	"encoding/hex"

	"github.com/11090815/mayy/common/utils"
	"github.com/11090815/mayy/core/ledger"
	"github.com/11090815/mayy/errors"
	"github.com/11090815/mayy/protobuf/pgossip"
	"github.com/11090815/mayy/protobuf/pledger/rwset"
	"github.com/11090815/mayy/protobuf/ppeer"
	"google.golang.org/protobuf/proto"
)

// PvtDataCollections 类型封装了私有数据集合。
type PvtDataCollections []*ledger.TxPvtData

type PrivateRWSetWithConfig struct {
	RWSet            []PrivateRWSet
	CollectionConfig *ppeer.CollectionConfig
}

func (pdc *PvtDataCollections) Marshal() ([][]byte, error) {
	pvtDataBytes := make([][]byte, 0)
	for i, txPvtData := range *pdc {
		if txPvtData == nil {
			return nil, errors.NewErrorf("rwset index %d is nil", i)
		}
		pvtBytes, err := proto.Marshal(txPvtData.WriteSet)
		if err != nil {
			return nil, errors.NewError(err.Error())
		}
		pvtDataPayload := &pgossip.PvtDataPayload{TxSeqInBlock: txPvtData.SeqInBlock, Payload: pvtBytes}
		payloadBytes, err := proto.Marshal(pvtDataPayload)
		if err != nil {
			return nil, errors.NewError(err.Error())
		}
		pvtDataBytes = append(pvtDataBytes, payloadBytes)
	}
	return pvtDataBytes, nil
}

func (pdc *PvtDataCollections) Unmarshal(data [][]byte) error {
	for _, payloadBytes := range data {
		pvtDataPayload := &pgossip.PvtDataPayload{}
		if err := proto.Unmarshal(payloadBytes, pvtDataPayload); err != nil {
			return errors.NewError(err.Error())
		}
		txPvtReadWriteSet := &rwset.TxPvtReadWriteSet{}
		if err := proto.Unmarshal(pvtDataPayload.Payload, txPvtReadWriteSet); err != nil {
			return errors.NewError(err.Error())
		}
		*pdc = append(*pdc, &ledger.TxPvtData{
			SeqInBlock: pvtDataPayload.TxSeqInBlock,
			WriteSet:   txPvtReadWriteSet,
		})
	}
	return nil
}

/* ------------------------------------------------------------------------------------------ */

type PrivateRWSet []byte

func (prws PrivateRWSet) Digest() string {
	return hex.EncodeToString(utils.ComputeSHA256(prws))
}

func PrivateRWSets(rwsets ...PrivateRWSet) [][]byte {
	var res [][]byte
	for _, rws := range rwsets {
		res = append(res, rws)
	}
	return res
}
