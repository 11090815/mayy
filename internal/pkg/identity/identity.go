package identity

// Serializer 是一个定义了 Serialize 方法的接口，该接口期待一个能够代表“身份”的结构体，
// 可以实现 Serialize 方法，从而将“身份”结构体序列化成一个字节数组。
type Serializer interface {
	Serialize() ([]byte, error)
}
