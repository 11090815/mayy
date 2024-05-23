package channelconfig

type Org interface {
	Name() string

	MSPID() string

	MSP()
}