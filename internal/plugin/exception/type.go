package exception

//ErrFieldIdentifierError（字段标识错误）
//含义: 该错误表示协议中指定的字段标识符无效或错误。字段标识符用于标识数据包中的特定字段，如果这个标识符不正确或不匹配协议的定义，就会导致这个错误。如未知功能码
//可能原因: 字段标识符拼写错误、字段标识符不符合协议规范、数据包中存在未知或非法的字段标识符。
//2. ErrValueOutOfRange（取值超出范围）
//含义: 该错误表示某个字段的值超出了协议定义的有效范围。每个字段通常都有一个预定义的取值范围，超出该范围的值将被认为是不合法的。
//可能原因: 数据输入错误、传感器或设备故障导致的异常值、协议实现不一致。
//3. ErrAssociatedValueError（关联取值错误）
//含义: 该错误表示某个字段的值与其他字段或系统状态的预期值不一致。这通常涉及到字段之间的逻辑关系或依赖关系。
//可能原因: 数据间的逻辑关系被破坏、传输过程中的数据损坏、数据校验失败。
//4. ErrInternalLengthError（内部长度错误）
//含义: 该错误表示数据包的某个部分或字段的长度与协议中定义的长度不匹配。内部长度错误通常涉及数据包的结构或字段的长度。
//可能原因: 数据包格式错误、协议实现不一致、数据截断或填充错误。
//5. ErrTotalLengthError（包总长度错误）
//含义: 该错误表示数据包的总长度与协议定义的长度不一致。总长度错误涉及到整个数据包的长度校验。
//可能原因: 数据包损坏、数据截断或冗余、协议实现不一致。
//6. ErrDataEncodingError（数据编码错误）
//含义: 该错误表示数据在编码或解码过程中出现了问题。这可能涉及到数据的格式、编码规则或字符集。
//可能原因: 编码方式不匹配、数据格式错误、编码器或解码器故障。
//7. ErrUnitDataError（单元数据错误）
//含义: 该错误表示某个数据单元或数据块出现了错误。单元数据错误通常指的是数据的基本单元，如字节、字、双字等。
//可能原因: 数据单元格式错误、数据读取或写入错误、协议实现不一致。
//8. ErrDataChecksumError（数据校验错误）
//含义: 该错误表示数据的校验和或哈希值计算结果不正确。数据校验错误通常用于检测数据在传输过程中是否发生了损坏。
//可能原因: 数据在传输过程中损坏、校验和算法错误、数据被篡改。
type ErrType uint8

const (
	ProtocolOK              ErrType = iota // 正常
	ErrFieldIdentifierError                // 字段标识错误
	ErrValueOutOfRange                     // 取值超出范围
	ErrAssociatedValueError                // 关联取值错误
	ErrInternalLengthError                 // 内部长度错误
	ErrTotalLengthError                    // 包总长度错误
	ErrDataEncodingError                   // 数据编码错误
	ErrUnitDataError                       // 单元数据错误
	ErrDataChecksumError                   // 数据校验错误
	ErrDataFormat                          // 数据包格式错误
)

func (ErrType) GetErrType(check string) ErrType {
	switch check {
	case "未知功能码":
		return ErrFieldIdentifierError
	case "状态异常":
		return ErrUnitDataError
	case "数据包格式错误":
		return ErrDataFormat
	case "数据包的实际长度与协议头中声明的长度不一致":
		return ErrTotalLengthError
	default:
		return ProtocolOK
	}
}
