[toc]

## 1. 编程方面的问题

### 1.1 关于方法的 receiver 带不带星号 * 的问题

- 方法的 receiver 是类型的实例指针变量（带星号 *）

如果方法体内有对结构体字段进行修改的操作，那么无论类型的实例是不是指针，调用此方法都会造成结构体字段发生实质性的改变。

- 方法的 receiver 是类型的实例变量（不带星号 *）

如果方法体内有对结构体字段进行修改的操作，那么无论类型的实例是不是指针，调用此方法都不会造成结构体字段发生实质性的改变。

### 1.2 深拷贝与浅拷贝的区别

浅拷贝（Shallow Clone）：将 src 浅拷贝给 dst，对 dst 进行改变的话，src 也会跟着改变。

深拷贝（Deep Clone）：将 src 深拷贝给 dst，对 dst 进行改变的话，src 不会跟着改变。

定义两个结构体：
```go
type Address struct {
	Province string
}

type Student struct {
	Name string
	Home *Address
}
```

浅拷贝的例子：
```go
func TestShallowClone(t *testing.T) {
	stu1 := &Student{
		Name: "tom",
		Home: &Address{
			Province: "安徽",
		},
	}
	
	stu2 := stu1

	t.Logf("student1 {name: %s, home: %s}", stu1.Name, stu1.Home.Province) // output: student1 {name: tom, home: 安徽}
	t.Logf("student2 {name: %s, home: %s}", stu2.Name, stu2.Home.Province) // output: student2 {name: tom, home: 安徽}
	
	stu2.Name = "alice"
	stu2.Home.Province = "河南"

	t.Logf("student1 {name: %s, home: %s}", stu1.Name, stu1.Home.Province) // output: student1 {name: alice, home: 河南}
	t.Logf("student2 {name: %s, home: %s}", stu2.Name, stu2.Home.Province) // output: student2 {name: alice, home: 河南}
}
```

深拷贝的例子：
```go
func TestDeepClone(t *testing.T) {
	stu1 := &Student{
		Name: "tom",
		Home: &Address{
			Province: "安徽",
		},
	}
	
	tmp := *stu1
	tmpHome := *stu1.Home
	tmp.Home = &tmpHome

	stu2 := &tmp

	t.Logf("student1 {name: %s, home: %s}", stu1.Name, stu1.Home.Province) // output: student1 {name: tom, home: 安徽}
	t.Logf("student2 {name: %s, home: %s}", stu2.Name, stu2.Home.Province) // output: student2 {name: tom, home: 安徽}
	
	stu2.Name = "alice"
	stu2.Home.Province = "河南"

	t.Logf("student1 {name: %s, home: %s}", stu1.Name, stu1.Home.Province) // output: student1 {name: tom, home: 安徽}
	t.Logf("student2 {name: %s, home: %s}", stu2.Name, stu2.Home.Province) // output: student2 {name: alice, home: 河南}
}
```

关于 golang 拷贝的优质文章可参考：https://zhuanlan.zhihu.com/p/161210711。

## 2. 密码学方面的问题

### 2.1 ECDSA 签名的伪造问题

ECDSA 的签名生成过程如下：

1. 随机选择密钥 $sk \leftarrow Z_p^*$，利用基点 $G$ 计算公钥 $pk = k \cdot G$；

2. 选择一个随机数 $k \leftarrow Z_p^*$，计算点 $K= k \cdot G$，取 $K$ 的 $x$ 坐标轴上的值 $x_K$，让 $r = x_K$。

3. 计算消息 $m$ 的摘要值 $h = H(m)$；

4. 计算签名 $s= k^{-1}(h + r \cdot sk)$；

5. 返回签名 $(r,s)$。

ECDSA 的签名验证过程如下：

1. 计算消息 $m$ 的摘要值 $h = H(m)$；

2. 计算签名的逆元 $s^{-1}$；

3. 计算点 $K' = (h \cdot s^{-1}) \cdot G + (r \cdot s^{-1}) \cdot pk$；

4. 对比 $r$ 与 $K'$ 的 $x$ 轴上的值 $x_{K'}$ 是否相同。

在上述签名验证过程中，只要 $r$ 正确，签名验证就会通过；$s$ 的作用是计算点 $K'$，只要点 $K'$ 的 $x$ 坐标等于 $r$，$s$ 取什么值不重要。因此，如果有多个 $s$ 值可以导致一个具有与 $r$ 相等的 $x$ 坐标的点 $K$，则对于给定的公钥和消息摘要存在多个有效签名。一个非常显而易见的情况是，$K$ 是椭圆曲线上的一个点，在曲线上也有一个具有与点 $K$ 关于 $x$ 轴对称的点 $-K$。这就导致 $(r,s)$ 和 $(r, -s \ mod \ p)$ 都是有效签名。

对于上述问题，比特币采用的解决办法是：确保计算出来的 $s$ 小于或等于曲线阶数的一半。