// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.1
// 	protoc        v3.12.4
// source: auth_service.proto

package grpc_auth_server

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

type GetTokenRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Email string `protobuf:"bytes,1,opt,name=email,proto3" json:"email,omitempty"`
}

func (x *GetTokenRequest) Reset() {
	*x = GetTokenRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetTokenRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetTokenRequest) ProtoMessage() {}

func (x *GetTokenRequest) ProtoReflect() protoreflect.Message {
	mi := &file_auth_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetTokenRequest.ProtoReflect.Descriptor instead.
func (*GetTokenRequest) Descriptor() ([]byte, []int) {
	return file_auth_service_proto_rawDescGZIP(), []int{0}
}

func (x *GetTokenRequest) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

type GetTokenResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Code  int64  `protobuf:"varint,1,opt,name=code,proto3" json:"code,omitempty"`
	Token string `protobuf:"bytes,2,opt,name=token,proto3" json:"token,omitempty"`
}

func (x *GetTokenResponse) Reset() {
	*x = GetTokenResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetTokenResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetTokenResponse) ProtoMessage() {}

func (x *GetTokenResponse) ProtoReflect() protoreflect.Message {
	mi := &file_auth_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetTokenResponse.ProtoReflect.Descriptor instead.
func (*GetTokenResponse) Descriptor() ([]byte, []int) {
	return file_auth_service_proto_rawDescGZIP(), []int{1}
}

func (x *GetTokenResponse) GetCode() int64 {
	if x != nil {
		return x.Code
	}
	return 0
}

func (x *GetTokenResponse) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

type IsTokenValidRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Token string `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
}

func (x *IsTokenValidRequest) Reset() {
	*x = IsTokenValidRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IsTokenValidRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IsTokenValidRequest) ProtoMessage() {}

func (x *IsTokenValidRequest) ProtoReflect() protoreflect.Message {
	mi := &file_auth_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IsTokenValidRequest.ProtoReflect.Descriptor instead.
func (*IsTokenValidRequest) Descriptor() ([]byte, []int) {
	return file_auth_service_proto_rawDescGZIP(), []int{2}
}

func (x *IsTokenValidRequest) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

type IsTokenValidResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Code         int64  `protobuf:"varint,1,opt,name=code,proto3" json:"code,omitempty"`
	IsTokenValid bool   `protobuf:"varint,2,opt,name=is_token_valid,json=isTokenValid,proto3" json:"is_token_valid,omitempty"`
	Email        string `protobuf:"bytes,3,opt,name=email,proto3" json:"email,omitempty"`
}

func (x *IsTokenValidResponse) Reset() {
	*x = IsTokenValidResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IsTokenValidResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IsTokenValidResponse) ProtoMessage() {}

func (x *IsTokenValidResponse) ProtoReflect() protoreflect.Message {
	mi := &file_auth_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IsTokenValidResponse.ProtoReflect.Descriptor instead.
func (*IsTokenValidResponse) Descriptor() ([]byte, []int) {
	return file_auth_service_proto_rawDescGZIP(), []int{3}
}

func (x *IsTokenValidResponse) GetCode() int64 {
	if x != nil {
		return x.Code
	}
	return 0
}

func (x *IsTokenValidResponse) GetIsTokenValid() bool {
	if x != nil {
		return x.IsTokenValid
	}
	return false
}

func (x *IsTokenValidResponse) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

var File_auth_service_proto protoreflect.FileDescriptor

var file_auth_service_proto_rawDesc = []byte{
	0x0a, 0x12, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x67, 0x72, 0x70, 0x63, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x22, 0x27, 0x0a, 0x0f, 0x47, 0x65, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x22, 0x3c, 0x0a, 0x10, 0x47, 0x65,
	0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x12,
	0x0a, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x04, 0x63, 0x6f,
	0x64, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x2b, 0x0a, 0x13, 0x49, 0x73, 0x54, 0x6f,
	0x6b, 0x65, 0x6e, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x66, 0x0a, 0x14, 0x49, 0x73, 0x54, 0x6f, 0x6b, 0x65, 0x6e,
	0x56, 0x61, 0x6c, 0x69, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x12, 0x0a,
	0x04, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x04, 0x63, 0x6f, 0x64,
	0x65, 0x12, 0x24, 0x0a, 0x0e, 0x69, 0x73, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x5f, 0x76, 0x61,
	0x6c, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0c, 0x69, 0x73, 0x54, 0x6f, 0x6b,
	0x65, 0x6e, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x32, 0xaf, 0x01,
	0x0a, 0x0b, 0x41, 0x75, 0x74, 0x68, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x49, 0x0a,
	0x08, 0x47, 0x65, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x1c, 0x2e, 0x67, 0x72, 0x70, 0x63,
	0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x47, 0x65, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1d, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x5f, 0x63,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x47, 0x65, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x55, 0x0a, 0x0c, 0x49, 0x73, 0x54, 0x6f,
	0x6b, 0x65, 0x6e, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x12, 0x20, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x5f,
	0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x49, 0x73, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x56, 0x61,
	0x6c, 0x69, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x21, 0x2e, 0x67, 0x72, 0x70,
	0x63, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x49, 0x73, 0x54, 0x6f, 0x6b, 0x65, 0x6e,
	0x56, 0x61, 0x6c, 0x69, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42,
	0x41, 0x5a, 0x3f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x61, 0x74,
	0x72, 0x61, 0x72, 0x69, 0x6b, 0x73, 0x61, 0x2f, 0x6b, 0x65, 0x6e, 0x61, 0x6c, 0x61, 0x6e, 0x2d,
	0x61, 0x75, 0x74, 0x68, 0x2f, 0x61, 0x70, 0x70, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61,
	0x6c, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x73, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_auth_service_proto_rawDescOnce sync.Once
	file_auth_service_proto_rawDescData = file_auth_service_proto_rawDesc
)

func file_auth_service_proto_rawDescGZIP() []byte {
	file_auth_service_proto_rawDescOnce.Do(func() {
		file_auth_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_auth_service_proto_rawDescData)
	})
	return file_auth_service_proto_rawDescData
}

var file_auth_service_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_auth_service_proto_goTypes = []interface{}{
	(*GetTokenRequest)(nil),      // 0: grpc_client.GetTokenRequest
	(*GetTokenResponse)(nil),     // 1: grpc_client.GetTokenResponse
	(*IsTokenValidRequest)(nil),  // 2: grpc_client.IsTokenValidRequest
	(*IsTokenValidResponse)(nil), // 3: grpc_client.IsTokenValidResponse
}
var file_auth_service_proto_depIdxs = []int32{
	0, // 0: grpc_client.AuthService.GetToken:input_type -> grpc_client.GetTokenRequest
	2, // 1: grpc_client.AuthService.IsTokenValid:input_type -> grpc_client.IsTokenValidRequest
	1, // 2: grpc_client.AuthService.GetToken:output_type -> grpc_client.GetTokenResponse
	3, // 3: grpc_client.AuthService.IsTokenValid:output_type -> grpc_client.IsTokenValidResponse
	2, // [2:4] is the sub-list for method output_type
	0, // [0:2] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_auth_service_proto_init() }
func file_auth_service_proto_init() {
	if File_auth_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_auth_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetTokenRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetTokenResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IsTokenValidRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IsTokenValidResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_auth_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_auth_service_proto_goTypes,
		DependencyIndexes: file_auth_service_proto_depIdxs,
		MessageInfos:      file_auth_service_proto_msgTypes,
	}.Build()
	File_auth_service_proto = out.File
	file_auth_service_proto_rawDesc = nil
	file_auth_service_proto_goTypes = nil
	file_auth_service_proto_depIdxs = nil
}
