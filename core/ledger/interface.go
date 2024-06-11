package ledger

import "github.com/11090815/mayy/protobuf/pledger/rwset"

// TxPvtData 封装了 tx 的 id 号和 tx 的 pvt 写集。
type TxPvtData struct {
	SeqInBlock uint64
	WriteSet   *rwset.TxPvtReadWriteSet
}
