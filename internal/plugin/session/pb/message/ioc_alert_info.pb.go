// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.3
// 	protoc        v5.29.0
// source: message/ioc_alert_info.proto

package push_model

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type IOC_ALERT_INFO struct {
	state              protoimpl.MessageState `protogen:"open.v1"`
	IocId              *string                `protobuf:"bytes,1,req,name=ioc_id,json=iocId" json:"ioc_id,omitempty"`                                           //	IOC编号
	IocValue           *string                `protobuf:"bytes,2,req,name=ioc_value,json=iocValue" json:"ioc_value,omitempty"`                                  //	IOC内容
	IocCategory        *string                `protobuf:"bytes,3,req,name=ioc_category,json=iocCategory" json:"ioc_category,omitempty"`                         //	IOC策略	IP_PORT、DOMAIN、URL、HASH、TPD…
	IocPublicDate      *uint64                `protobuf:"varint,4,req,name=ioc_public_date,json=iocPublicDate" json:"ioc_public_date,omitempty"`                //	IOC发布时间
	IocAlertName       *string                `protobuf:"bytes,5,req,name=ioc_alert_name,json=iocAlertName" json:"ioc_alert_name,omitempty"`                    //	IOC告警名称
	IocCurrentStatus   *string                `protobuf:"bytes,6,req,name=ioc_current_status,json=iocCurrentStatus" json:"ioc_current_status,omitempty"`        //	IOC当前状态	"active/inactive/sinkhole/unknown具体含义为：1.active即活跃:当前观察到此IOC的活动2.inactive即非活跃：当前此IOC处于不活动状态，如休眠期等；3.sinkhole：表示此IOC（域名类）处于黑洞状态，或接管状态4.unknown：当前没有观察到此IOC的状态，此IOC依然是有效的威胁"
	IocHot             *bool                  `protobuf:"varint,7,opt,name=ioc_hot,json=iocHot" json:"ioc_hot,omitempty"`                                       //	IOC热点状态	True/False
	IocFirstSeen       *string                `protobuf:"bytes,8,opt,name=ioc_first_seen,json=iocFirstSeen" json:"ioc_first_seen,omitempty"`                    //	首次发现时间	情报的首次发现时间
	IocLastDetection   *string                `protobuf:"bytes,9,req,name=ioc_last_detection,json=iocLastDetection" json:"ioc_last_detection,omitempty"`        //	最近检测时间	最后一次检测到攻击的时间
	IocRefer           *string                `protobuf:"bytes,10,opt,name=ioc_refer,json=iocRefer" json:"ioc_refer,omitempty"`                                 //	参考文档报告
	IocReportData      *string                `protobuf:"bytes,11,opt,name=ioc_report_data,json=iocReportData" json:"ioc_report_data,omitempty"`                //	报告发布时间
	IocReportVendor    *string                `protobuf:"bytes,12,opt,name=ioc_report_vendor,json=iocReportVendor" json:"ioc_report_vendor,omitempty"`          //	报告发布厂商
	IocType            *string                `protobuf:"bytes,13,req,name=ioc_type,json=iocType" json:"ioc_type,omitempty"`                                    //	IOC类型	"General：混合功能远控端；Connect：受控后上报配置信息，用于上线和命令控制分离的场景；Download：下载恶意软件组件；C2：命令控制通道；Dataleak：连接数据放置功能的服务器。"
	IocTargeted        *bool                  `protobuf:"varint,14,req,name=ioc_targeted,json=iocTargeted" json:"ioc_targeted,omitempty"`                       //	定向攻击标识	True/False
	IocMaliciousFamily *string                `protobuf:"bytes,15,opt,name=ioc_malicious_family,json=iocMaliciousFamily" json:"ioc_malicious_family,omitempty"` //	恶意代码家族
	IocAptCampaign     *string                `protobuf:"bytes,16,opt,name=ioc_apt_campaign,json=iocAptCampaign" json:"ioc_apt_campaign,omitempty"`             //	APT组织名称	对应actor、primary_name
	IocAptAlias        *string                `protobuf:"bytes,17,opt,name=ioc_apt_alias,json=iocAptAlias" json:"ioc_apt_alias,omitempty"`                      //	APT组织别名
	IocAptCountry      *string                `protobuf:"bytes,18,opt,name=ioc_apt_country,json=iocAptCountry" json:"ioc_apt_country,omitempty"`                //	APT所属国家
	IocAptMission      *string                `protobuf:"bytes,19,opt,name=ioc_apt_mission,json=iocAptMission" json:"ioc_apt_mission,omitempty"`                //	APT行动名称
	IocRat             *string                `protobuf:"bytes,20,opt,name=ioc_rat,json=iocRat" json:"ioc_rat,omitempty"`                                       //	远控工具
	IocAttackMethod    *string                `protobuf:"bytes,21,opt,name=ioc_attack_method,json=iocAttackMethod" json:"ioc_attack_method,omitempty"`          //	攻击手法	WEB攻击渗透、…
	IocVul             *string                `protobuf:"bytes,22,opt,name=ioc_vul,json=iocVul" json:"ioc_vul,omitempty"`                                       //	关联漏洞	攻击者所用到的漏洞
	IocAffectedSector  *string                `protobuf:"bytes,23,opt,name=ioc_affected_sector,json=iocAffectedSector" json:"ioc_affected_sector,omitempty"`    //	影响行业
	IocAffectedProduct *string                `protobuf:"bytes,24,opt,name=ioc_affected_product,json=iocAffectedProduct" json:"ioc_affected_product,omitempty"` //	影响平台
	IocDetailInfo      *string                `protobuf:"bytes,25,req,name=ioc_detail_info,json=iocDetailInfo" json:"ioc_detail_info,omitempty"`                //	威胁详情描述	"威胁详情：漏洞详情：修复方案："
	unknownFields      protoimpl.UnknownFields
	sizeCache          protoimpl.SizeCache
}

func (x *IOC_ALERT_INFO) Reset() {
	*x = IOC_ALERT_INFO{}
	mi := &file_message_ioc_alert_info_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *IOC_ALERT_INFO) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IOC_ALERT_INFO) ProtoMessage() {}

func (x *IOC_ALERT_INFO) ProtoReflect() protoreflect.Message {
	mi := &file_message_ioc_alert_info_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IOC_ALERT_INFO.ProtoReflect.Descriptor instead.
func (*IOC_ALERT_INFO) Descriptor() ([]byte, []int) {
	return file_message_ioc_alert_info_proto_rawDescGZIP(), []int{0}
}

func (x *IOC_ALERT_INFO) GetIocId() string {
	if x != nil && x.IocId != nil {
		return *x.IocId
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocValue() string {
	if x != nil && x.IocValue != nil {
		return *x.IocValue
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocCategory() string {
	if x != nil && x.IocCategory != nil {
		return *x.IocCategory
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocPublicDate() uint64 {
	if x != nil && x.IocPublicDate != nil {
		return *x.IocPublicDate
	}
	return 0
}

func (x *IOC_ALERT_INFO) GetIocAlertName() string {
	if x != nil && x.IocAlertName != nil {
		return *x.IocAlertName
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocCurrentStatus() string {
	if x != nil && x.IocCurrentStatus != nil {
		return *x.IocCurrentStatus
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocHot() bool {
	if x != nil && x.IocHot != nil {
		return *x.IocHot
	}
	return false
}

func (x *IOC_ALERT_INFO) GetIocFirstSeen() string {
	if x != nil && x.IocFirstSeen != nil {
		return *x.IocFirstSeen
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocLastDetection() string {
	if x != nil && x.IocLastDetection != nil {
		return *x.IocLastDetection
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocRefer() string {
	if x != nil && x.IocRefer != nil {
		return *x.IocRefer
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocReportData() string {
	if x != nil && x.IocReportData != nil {
		return *x.IocReportData
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocReportVendor() string {
	if x != nil && x.IocReportVendor != nil {
		return *x.IocReportVendor
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocType() string {
	if x != nil && x.IocType != nil {
		return *x.IocType
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocTargeted() bool {
	if x != nil && x.IocTargeted != nil {
		return *x.IocTargeted
	}
	return false
}

func (x *IOC_ALERT_INFO) GetIocMaliciousFamily() string {
	if x != nil && x.IocMaliciousFamily != nil {
		return *x.IocMaliciousFamily
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocAptCampaign() string {
	if x != nil && x.IocAptCampaign != nil {
		return *x.IocAptCampaign
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocAptAlias() string {
	if x != nil && x.IocAptAlias != nil {
		return *x.IocAptAlias
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocAptCountry() string {
	if x != nil && x.IocAptCountry != nil {
		return *x.IocAptCountry
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocAptMission() string {
	if x != nil && x.IocAptMission != nil {
		return *x.IocAptMission
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocRat() string {
	if x != nil && x.IocRat != nil {
		return *x.IocRat
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocAttackMethod() string {
	if x != nil && x.IocAttackMethod != nil {
		return *x.IocAttackMethod
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocVul() string {
	if x != nil && x.IocVul != nil {
		return *x.IocVul
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocAffectedSector() string {
	if x != nil && x.IocAffectedSector != nil {
		return *x.IocAffectedSector
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocAffectedProduct() string {
	if x != nil && x.IocAffectedProduct != nil {
		return *x.IocAffectedProduct
	}
	return ""
}

func (x *IOC_ALERT_INFO) GetIocDetailInfo() string {
	if x != nil && x.IocDetailInfo != nil {
		return *x.IocDetailInfo
	}
	return ""
}

var File_message_ioc_alert_info_proto protoreflect.FileDescriptor

var file_message_ioc_alert_info_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2f, 0x69, 0x6f, 0x63, 0x5f, 0x61, 0x6c,
	0x65, 0x72, 0x74, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x22, 0xb7, 0x07, 0x0a, 0x0e, 0x49, 0x4f, 0x43, 0x5f,
	0x41, 0x4c, 0x45, 0x52, 0x54, 0x5f, 0x49, 0x4e, 0x46, 0x4f, 0x12, 0x15, 0x0a, 0x06, 0x69, 0x6f,
	0x63, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x02, 0x28, 0x09, 0x52, 0x05, 0x69, 0x6f, 0x63, 0x49,
	0x64, 0x12, 0x1b, 0x0a, 0x09, 0x69, 0x6f, 0x63, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02,
	0x20, 0x02, 0x28, 0x09, 0x52, 0x08, 0x69, 0x6f, 0x63, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x21,
	0x0a, 0x0c, 0x69, 0x6f, 0x63, 0x5f, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x18, 0x03,
	0x20, 0x02, 0x28, 0x09, 0x52, 0x0b, 0x69, 0x6f, 0x63, 0x43, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72,
	0x79, 0x12, 0x26, 0x0a, 0x0f, 0x69, 0x6f, 0x63, 0x5f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f,
	0x64, 0x61, 0x74, 0x65, 0x18, 0x04, 0x20, 0x02, 0x28, 0x04, 0x52, 0x0d, 0x69, 0x6f, 0x63, 0x50,
	0x75, 0x62, 0x6c, 0x69, 0x63, 0x44, 0x61, 0x74, 0x65, 0x12, 0x24, 0x0a, 0x0e, 0x69, 0x6f, 0x63,
	0x5f, 0x61, 0x6c, 0x65, 0x72, 0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x02, 0x28,
	0x09, 0x52, 0x0c, 0x69, 0x6f, 0x63, 0x41, 0x6c, 0x65, 0x72, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0x12,
	0x2c, 0x0a, 0x12, 0x69, 0x6f, 0x63, 0x5f, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x5f, 0x73,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x06, 0x20, 0x02, 0x28, 0x09, 0x52, 0x10, 0x69, 0x6f, 0x63,
	0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x17, 0x0a,
	0x07, 0x69, 0x6f, 0x63, 0x5f, 0x68, 0x6f, 0x74, 0x18, 0x07, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06,
	0x69, 0x6f, 0x63, 0x48, 0x6f, 0x74, 0x12, 0x24, 0x0a, 0x0e, 0x69, 0x6f, 0x63, 0x5f, 0x66, 0x69,
	0x72, 0x73, 0x74, 0x5f, 0x73, 0x65, 0x65, 0x6e, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c,
	0x69, 0x6f, 0x63, 0x46, 0x69, 0x72, 0x73, 0x74, 0x53, 0x65, 0x65, 0x6e, 0x12, 0x2c, 0x0a, 0x12,
	0x69, 0x6f, 0x63, 0x5f, 0x6c, 0x61, 0x73, 0x74, 0x5f, 0x64, 0x65, 0x74, 0x65, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x18, 0x09, 0x20, 0x02, 0x28, 0x09, 0x52, 0x10, 0x69, 0x6f, 0x63, 0x4c, 0x61, 0x73,
	0x74, 0x44, 0x65, 0x74, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1b, 0x0a, 0x09, 0x69, 0x6f,
	0x63, 0x5f, 0x72, 0x65, 0x66, 0x65, 0x72, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x69,
	0x6f, 0x63, 0x52, 0x65, 0x66, 0x65, 0x72, 0x12, 0x26, 0x0a, 0x0f, 0x69, 0x6f, 0x63, 0x5f, 0x72,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0d, 0x69, 0x6f, 0x63, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x44, 0x61, 0x74, 0x61, 0x12,
	0x2a, 0x0a, 0x11, 0x69, 0x6f, 0x63, 0x5f, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x5f, 0x76, 0x65,
	0x6e, 0x64, 0x6f, 0x72, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x69, 0x6f, 0x63, 0x52,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x56, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x12, 0x19, 0x0a, 0x08, 0x69,
	0x6f, 0x63, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x0d, 0x20, 0x02, 0x28, 0x09, 0x52, 0x07, 0x69,
	0x6f, 0x63, 0x54, 0x79, 0x70, 0x65, 0x12, 0x21, 0x0a, 0x0c, 0x69, 0x6f, 0x63, 0x5f, 0x74, 0x61,
	0x72, 0x67, 0x65, 0x74, 0x65, 0x64, 0x18, 0x0e, 0x20, 0x02, 0x28, 0x08, 0x52, 0x0b, 0x69, 0x6f,
	0x63, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x65, 0x64, 0x12, 0x30, 0x0a, 0x14, 0x69, 0x6f, 0x63,
	0x5f, 0x6d, 0x61, 0x6c, 0x69, 0x63, 0x69, 0x6f, 0x75, 0x73, 0x5f, 0x66, 0x61, 0x6d, 0x69, 0x6c,
	0x79, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x09, 0x52, 0x12, 0x69, 0x6f, 0x63, 0x4d, 0x61, 0x6c, 0x69,
	0x63, 0x69, 0x6f, 0x75, 0x73, 0x46, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x12, 0x28, 0x0a, 0x10, 0x69,
	0x6f, 0x63, 0x5f, 0x61, 0x70, 0x74, 0x5f, 0x63, 0x61, 0x6d, 0x70, 0x61, 0x69, 0x67, 0x6e, 0x18,
	0x10, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x69, 0x6f, 0x63, 0x41, 0x70, 0x74, 0x43, 0x61, 0x6d,
	0x70, 0x61, 0x69, 0x67, 0x6e, 0x12, 0x22, 0x0a, 0x0d, 0x69, 0x6f, 0x63, 0x5f, 0x61, 0x70, 0x74,
	0x5f, 0x61, 0x6c, 0x69, 0x61, 0x73, 0x18, 0x11, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x69, 0x6f,
	0x63, 0x41, 0x70, 0x74, 0x41, 0x6c, 0x69, 0x61, 0x73, 0x12, 0x26, 0x0a, 0x0f, 0x69, 0x6f, 0x63,
	0x5f, 0x61, 0x70, 0x74, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79, 0x18, 0x12, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0d, 0x69, 0x6f, 0x63, 0x41, 0x70, 0x74, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x72,
	0x79, 0x12, 0x26, 0x0a, 0x0f, 0x69, 0x6f, 0x63, 0x5f, 0x61, 0x70, 0x74, 0x5f, 0x6d, 0x69, 0x73,
	0x73, 0x69, 0x6f, 0x6e, 0x18, 0x13, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x69, 0x6f, 0x63, 0x41,
	0x70, 0x74, 0x4d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x17, 0x0a, 0x07, 0x69, 0x6f, 0x63,
	0x5f, 0x72, 0x61, 0x74, 0x18, 0x14, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x69, 0x6f, 0x63, 0x52,
	0x61, 0x74, 0x12, 0x2a, 0x0a, 0x11, 0x69, 0x6f, 0x63, 0x5f, 0x61, 0x74, 0x74, 0x61, 0x63, 0x6b,
	0x5f, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x18, 0x15, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x69,
	0x6f, 0x63, 0x41, 0x74, 0x74, 0x61, 0x63, 0x6b, 0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x12, 0x17,
	0x0a, 0x07, 0x69, 0x6f, 0x63, 0x5f, 0x76, 0x75, 0x6c, 0x18, 0x16, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x06, 0x69, 0x6f, 0x63, 0x56, 0x75, 0x6c, 0x12, 0x2e, 0x0a, 0x13, 0x69, 0x6f, 0x63, 0x5f, 0x61,
	0x66, 0x66, 0x65, 0x63, 0x74, 0x65, 0x64, 0x5f, 0x73, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x18, 0x17,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x69, 0x6f, 0x63, 0x41, 0x66, 0x66, 0x65, 0x63, 0x74, 0x65,
	0x64, 0x53, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x12, 0x30, 0x0a, 0x14, 0x69, 0x6f, 0x63, 0x5f, 0x61,
	0x66, 0x66, 0x65, 0x63, 0x74, 0x65, 0x64, 0x5f, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x18,
	0x18, 0x20, 0x01, 0x28, 0x09, 0x52, 0x12, 0x69, 0x6f, 0x63, 0x41, 0x66, 0x66, 0x65, 0x63, 0x74,
	0x65, 0x64, 0x50, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x12, 0x26, 0x0a, 0x0f, 0x69, 0x6f, 0x63,
	0x5f, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x19, 0x20, 0x02,
	0x28, 0x09, 0x52, 0x0d, 0x69, 0x6f, 0x63, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66,
	0x6f, 0x42, 0x68, 0x0a, 0x21, 0x63, 0x6f, 0x6d, 0x2e, 0x6a, 0x75, 0x64, 0x67, 0x6d, 0x65, 0x6e,
	0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x6d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x0c, 0x49, 0x6f, 0x63, 0x41, 0x6c, 0x65, 0x72, 0x74,
	0x49, 0x6e, 0x66, 0x6f, 0x5a, 0x35, 0x64, 0x69, 0x73, 0x73, 0x65, 0x63, 0x74, 0x2f, 0x69, 0x6e,
	0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x2f, 0x73, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2f, 0x70, 0x62, 0x2f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x3b, 0x70, 0x75, 0x73, 0x68, 0x5f, 0x6d, 0x6f, 0x64, 0x65, 0x6c,
}

var (
	file_message_ioc_alert_info_proto_rawDescOnce sync.Once
	file_message_ioc_alert_info_proto_rawDescData = file_message_ioc_alert_info_proto_rawDesc
)

func file_message_ioc_alert_info_proto_rawDescGZIP() []byte {
	file_message_ioc_alert_info_proto_rawDescOnce.Do(func() {
		file_message_ioc_alert_info_proto_rawDescData = protoimpl.X.CompressGZIP(file_message_ioc_alert_info_proto_rawDescData)
	})
	return file_message_ioc_alert_info_proto_rawDescData
}

var file_message_ioc_alert_info_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_message_ioc_alert_info_proto_goTypes = []any{
	(*IOC_ALERT_INFO)(nil), // 0: Message.IOC_ALERT_INFO
}
var file_message_ioc_alert_info_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_message_ioc_alert_info_proto_init() }
func file_message_ioc_alert_info_proto_init() {
	if File_message_ioc_alert_info_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_message_ioc_alert_info_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_message_ioc_alert_info_proto_goTypes,
		DependencyIndexes: file_message_ioc_alert_info_proto_depIdxs,
		MessageInfos:      file_message_ioc_alert_info_proto_msgTypes,
	}.Build()
	File_message_ioc_alert_info_proto = out.File
	file_message_ioc_alert_info_proto_rawDesc = nil
	file_message_ioc_alert_info_proto_goTypes = nil
	file_message_ioc_alert_info_proto_depIdxs = nil
}
