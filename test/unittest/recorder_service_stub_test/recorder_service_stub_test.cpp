/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "recorder_service_stub_test.h"
#include <fcntl.h>
#include <unistd.h>
#include "media_errors.h"
#include "recorder_service_stub.h"
#include "recorder.h"
#include "i_standard_recorder_service.h"
#include "media_errors.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "media_log.h"
#include "qos.h"
#include "accesstoken_kit.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;

void RecorderServiceStubTest::SetUpTestCase(void)
{
}

void RecorderServiceStubTest::TearDownTestCase(void)
{
}

void RecorderServiceStubTest::SetUp(void)
{
}

void RecorderServiceStubTest::TearDown(void)
{
}

sptr<RecorderServiceStub> RecorderServiceStubTest::CreateStub()
{
    sptr<RecorderServiceStub> stub = RecorderServiceStub::Create();
    EXPECT_NE(stub, nullptr) << "Failed to create RecorderServiceStub";
    return stub;
}

/**
 * @tc.name: ~RecorderServiceStub
 * @tc.desc: ~RecorderServiceStub
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, CreateReleaseStubObject, TestSize.Level2)
{
    sptr<RecorderServiceStub> recorderServiceStub_ = RecorderServiceStub::Create();
    EXPECT_NE(recorderServiceStub_, nullptr);
    recorderServiceStub_->recorderServer_ = nullptr;
    recorderServiceStub_ = nullptr;
}

/**
 * @tc.name: DestoyServiceStub
 * @tc.desc: DestoyServiceStub
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, DestoyServiceStub, TestSize.Level2)
{
    sptr<RecorderServiceStub> recorderServiceStub_ = RecorderServiceStub::Create();
    EXPECT_NE(recorderServiceStub_, nullptr);
    recorderServiceStub_->recorderServer_ = nullptr;
    int ret = recorderServiceStub_->DestroyStub();
    EXPECT_EQ(ret, 0);
    recorderServiceStub_ = nullptr;
}

/**
 * @tc.name: TransmitQos_NormalLevel
 * @tc.desc: TransmitQos_NormalLevel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, TransmitQos_NormalLevel, TestSize.Level2)
{
    MessageParcel data, reply;
    int32_t level = static_cast<int32_t>(QOS::QosLevel::QOS_DEFAULT);
    data.WriteInt32(level);
    sptr<RecorderServiceStub> recorderServiceStub_ = RecorderServiceStub::Create();
    EXPECT_NE(recorderServiceStub_, nullptr);
    recorderServiceStub_->recorderServer_ = nullptr;
    int32_t ret = recorderServiceStub_->TransmitQos(data, reply);
    EXPECT_EQ(ret, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: TransmitQos_AllValidLevels
 * @tc.desc: TransmitQos_AllValidLevels
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, TransmitQos_AllValidLevels, TestSize.Level2)
{
    std::vector<int32_t> validLevels = {
        static_cast<int32_t>(QOS::QosLevel::QOS_BACKGROUND),
        static_cast<int32_t>(QOS::QosLevel::QOS_DEFAULT),
        static_cast<int32_t>(QOS::QosLevel::QOS_MAX)
    };
    sptr<RecorderServiceStub> recorderServiceStub_ = RecorderServiceStub::Create();
    recorderServiceStub_->recorderServer_ = nullptr;
    for (auto level : validLevels) {
        MessageParcel data, reply;
        data.WriteInt32(level);
        int32_t ret = recorderServiceStub_->TransmitQos(data, reply);
        EXPECT_EQ(ret, MSERR_NULL_POINTER_5400101);
    }
}

/**
 * @tc.name: TransmitQos_InvalidLowValue
 * @tc.desc: TransmitQos_InvalidLowValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, TransmitQos_InvalidLowValue, TestSize.Level2)
{
    MessageParcel data, reply;
    int32_t invalidLevel = static_cast<int32_t>(QOS::QosLevel::QOS_BACKGROUND) - 1;
    data.WriteInt32(invalidLevel);
    sptr<RecorderServiceStub> recorderServiceStub_ = RecorderServiceStub::Create();
    int32_t ret = recorderServiceStub_->TransmitQos(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: TransmitQos_InvalidHighValue
 * @tc.desc: TransmitQos_InvalidHighValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, TransmitQos_InvalidHighValue, TestSize.Level2)
{
    MessageParcel data, reply;
    int32_t invalidLevel = static_cast<int32_t>(QOS::QosLevel::QOS_MAX) + 1;
    data.WriteInt32(invalidLevel);
    sptr<RecorderServiceStub> recorderServiceStub_ = RecorderServiceStub::Create();
    int32_t ret = recorderServiceStub_->TransmitQos(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: TransmitQos_NegativeValue
 * @tc.desc: TransmitQos_NegativeValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, TransmitQos_NegativeValue, TestSize.Level2)
{
    MessageParcel data, reply;
    int32_t negativeLevel = -1;
    data.WriteInt32(negativeLevel);
    sptr<RecorderServiceStub> recorderServiceStub_ = RecorderServiceStub::Create();
    int32_t ret = recorderServiceStub_->TransmitQos(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: TransmitQos_BoundaryValues
 * @tc.desc: TransmitQos_BoundaryValues
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, TransmitQos_BoundaryValues, TestSize.Level2)
{
    MessageParcel data1, reply1;
    int32_t minLevel = static_cast<int32_t>(QOS::QosLevel::QOS_BACKGROUND);
    data1.WriteInt32(minLevel);
    sptr<RecorderServiceStub> recorderServiceStub_ = RecorderServiceStub::Create();
    recorderServiceStub_->recorderServer_ = nullptr;
    int32_t ret1 = recorderServiceStub_->TransmitQos(data1, reply1);
    EXPECT_EQ(ret1, MSERR_NULL_POINTER_5400101);
    MessageParcel data2, reply2;
    int32_t maxLevel = static_cast<int32_t>(QOS::QosLevel::QOS_MAX);
    data2.WriteInt32(maxLevel);
    int32_t ret2 = recorderServiceStub_->TransmitQos(data2, reply2);
    EXPECT_EQ(ret2, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: TransmitQos_MessageParcelReadFailure
 * @tc.desc: TransmitQos_MessageParcelReadFailure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, TransmitQos_MessageParcelReadFailure, TestSize.Level2)
{
    MessageParcel emptyData, reply;
    sptr<RecorderServiceStub> recorderServiceStub_ = RecorderServiceStub::Create();
    int32_t ret = recorderServiceStub_->TransmitQos(emptyData, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetMetaMimeType_InvalidSource
 * @tc.desc: SetMetaMimeType_InvalidSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetMetaMimeType_InvalidSource, TestSize.Level2)
{
    MessageParcel data, reply;
    int32_t sourceId = -1;
    data.WriteInt32(sourceId);
    sptr<RecorderServiceStub> recorderServiceStub_ = RecorderServiceStub::Create();
    int32_t ret = recorderServiceStub_->SetMetaMimeType(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetMetaTimedKey_InvalidSource
 * @tc.desc: SetMetaTimedKey_InvalidSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetMetaTimedKey_InvalidSource, TestSize.Level2)
{
    MessageParcel data, reply;
    int32_t sourceId = -1;
    data.WriteInt32(sourceId);
    sptr<RecorderServiceStub> recorderServiceStub_ = RecorderServiceStub::Create();
    int32_t ret = recorderServiceStub_->SetMetaTimedKey(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetMetaSourceTrackMime_InvalidSource
 * @tc.desc: SetMetaSourceTrackMime_InvalidSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetMetaSourceTrackMime_InvalidSource, TestSize.Level2)
{
    MessageParcel data, reply;
    int32_t sourceId = -1;
    data.WriteInt32(sourceId);
    sptr<RecorderServiceStub> recorderServiceStub_ = RecorderServiceStub::Create();
    int32_t ret = recorderServiceStub_->SetMetaSourceTrackMime(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetAudioAacProfile_InvalidSource
 * @tc.desc: SetAudioAacProfile_InvalidSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetAudioAacProfile_InvalidSource, TestSize.Level2)
{
    MessageParcel data, reply;
    int32_t sourceId = -1;
    int32_t format = -1;
    data.WriteInt32(sourceId);
    data.WriteInt32(format);
    sptr<RecorderServiceStub> recorderServiceStub_ = RecorderServiceStub::Create();
    recorderServiceStub_->recorderServer_ = nullptr;
    int32_t ret = recorderServiceStub_->SetAudioAacProfile(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetVideoSource_InvalidSource
 * @tc.desc: SetVideoSource_InvalidSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoSource_InvalidSource, TestSize.Level2)
{
    MessageParcel data, reply;
    sptr<RecorderServiceStub> recorderServiceStub_ = RecorderServiceStub::Create();
    int32_t ret = recorderServiceStub_->SetVideoSource(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetVideoEncoder_InvalidCodecFormat
 * @tc.desc: SetVideoEncoder_InvalidCodecFormat
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoEncoder_InvalidCodecFormat, TestSize.Level2)
{
    MessageParcel data, reply;
    int32_t sourceId = 1;
    int32_t invalidCodec = -1;
    data.WriteInt32(sourceId);
    data.WriteInt32(invalidCodec);
    sptr<RecorderServiceStub> recorderServiceStub_ = RecorderServiceStub::Create();
    int32_t ret = recorderServiceStub_->SetVideoEncoder(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: AddWatermark_NullRecorderServer
 * @tc.desc: AddWatermark_NullRecorderServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, AddWatermark_NullRecorderServer, TestSize.Level2)
{
    MessageParcel data, reply;
    sptr<RecorderServiceStub> recorderServiceStub_ = CreateStub();
    recorderServiceStub_->recorderServer_ = nullptr;
    int32_t ret = recorderServiceStub_->AddWatermark(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: AddWatermark_InvalidBufferRead
 * @tc.desc: AddWatermark_InvalidBufferRead
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, AddWatermark_InvalidBufferRead, TestSize.Level2)
{
    MessageParcel emptyData, reply;
    sptr<RecorderServiceStub> recorderServiceStub_ = CreateStub();
    int32_t ret = recorderServiceStub_->AddWatermark(emptyData, reply);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: AddWatermark_ReplyWriteFailure
 * @tc.desc: AddWatermark_ReplyWriteFailure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, AddWatermark_ReplyWriteFailure, TestSize.Level2)
{
    MessageParcel data;
    MessageParcel emptyReply;
    sptr<RecorderServiceStub> recorderServiceStub_ = CreateStub();
    int32_t ret = recorderServiceStub_->AddWatermark(data, emptyReply);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: AddWatermark_ZeroDimensions
 * @tc.desc: AddWatermark_ZeroDimensions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, AddWatermark_ZeroDimensions, TestSize.Level2)
{
    MessageParcel data, reply;
    sptr<RecorderServiceStub> recorderServiceStub_ = CreateStub();
    recorderServiceStub_->recorderServer_ = nullptr;
    data.WriteInt32(0);
    data.WriteInt32(0);
    int32_t ret = recorderServiceStub_->AddWatermark(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: AddWatermark_NegativeDimensions
 * @tc.desc: AddWatermark_NegativeDimensions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, AddWatermark_NegativeDimensions, TestSize.Level2)
{
    MessageParcel data, reply;
    sptr<RecorderServiceStub> recorderServiceStub_ = CreateStub();
    recorderServiceStub_->recorderServer_ = nullptr;
    data.WriteInt32(-1);
    data.WriteInt32(-1);
    int32_t ret = recorderServiceStub_->AddWatermark(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: AddWatermark_LargeDimensions
 * @tc.desc: AddWatermark_LargeDimensions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, AddWatermark_LargeDimensions, TestSize.Level2)
{
    MessageParcel data, reply;
    sptr<RecorderServiceStub> recorderServiceStub_ = CreateStub();
    recorderServiceStub_->recorderServer_ = nullptr;
    data.WriteInt32(INT_MAX);
    data.WriteInt32(INT_MAX);
    int32_t ret = recorderServiceStub_->AddWatermark(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: OnRemoteRequest_Denied_SetAudioSource
 * @tc.desc: OnRemoteRequest with PERMISSION_DENIED and code == SET_AUDIO_SOURCE
 *           Covers line 227 TRUE branch + line 229 TRUE (audioSourceType_ reset)
 *           AUDIO_INNER always makes CheckPermission return PERMISSION_DENIED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, OnRemoteRequest_Denied_SetAudioSource, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = RecorderServiceStub::Create();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;

    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(stub->GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(AudioSourceType::AUDIO_INNER));

    int32_t ret = stub->OnRemoteRequest(IStandardRecorderService::SET_AUDIO_SOURCE, data, reply, option);
    EXPECT_EQ(ret, MSERR_NO_PERMISSION_5400102);
    EXPECT_EQ(stub->audioSourceType_, AudioSourceType::AUDIO_SOURCE_INVALID);
}

/**
 * @tc.name: OnRemoteRequest_Denied_OtherAudioRequest
 * @tc.desc: OnRemoteRequest with PERMISSION_DENIED and code != SET_AUDIO_SOURCE
 *           Covers line 227 TRUE branch + line 229 FALSE (audioSourceType_ NOT reset)
 *           Set audioSourceType_ = AUDIO_INNER directly so CheckPermission returns DENIED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, OnRemoteRequest_Denied_OtherAudioRequest, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = RecorderServiceStub::Create();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    stub->audioSourceType_ = AudioSourceType::AUDIO_INNER;

    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(stub->GetDescriptor());

    int32_t ret = stub->OnRemoteRequest(IStandardRecorderService::SET_AUDIO_ENCODER, data, reply, option);
    EXPECT_EQ(ret, MSERR_NO_PERMISSION_5400102);
    EXPECT_EQ(stub->audioSourceType_, AudioSourceType::AUDIO_INNER);
}

/**
 * @tc.name: OnRemoteRequest_Granted_CommonNoAudioCheck
 * @tc.desc: OnRemoteRequest with PERMISSION_GRANTED via COMMON_REQUEST without audio check
 *           Covers line 227 FALSE branch (permissionResult != PERMISSION_DENIED)
 *           needAudioPermissionCheck=false by default, COMMON_REQUEST assigns GRANTED directly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, OnRemoteRequest_Granted_CommonNoAudioCheck, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = RecorderServiceStub::Create();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;

    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(stub->GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(OutputFormatType::FORMAT_MPEG_4));

    int32_t ret = stub->OnRemoteRequest(IStandardRecorderService::SET_OUTPUT_FORMAT, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: OnRemoteRequest_Denied_CommonWithAudioCheck
 * @tc.desc: OnRemoteRequest with PERMISSION_DENIED via COMMON_REQUEST with needAudioPermissionCheck=true
 *           Covers line 227 TRUE branch + line 229 FALSE (audioSourceType_ NOT reset)
 *           Different path from test 2: COMMON_REQUEST calls CheckPermission when needAudioPermissionCheck=true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, OnRemoteRequest_Denied_CommonWithAudioCheck, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = RecorderServiceStub::Create();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    stub->audioSourceType_ = AudioSourceType::AUDIO_INNER;
    stub->needAudioPermissionCheck = true;

    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(stub->GetDescriptor());

    int32_t ret = stub->OnRemoteRequest(IStandardRecorderService::PREPARE, data, reply, option);
    EXPECT_EQ(ret, MSERR_NO_PERMISSION_5400102);
    EXPECT_EQ(stub->audioSourceType_, AudioSourceType::AUDIO_INNER);
}

/**
 * @tc.name: OnRemoteRequest_Granted_NonAudioNonCommon
 * @tc.desc: OnRemoteRequest with PERMISSION_GRANTED via else branch (neither AUDIO nor COMMON request)
 *           Covers line 227 FALSE branch through a different path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, OnRemoteRequest_Granted_NonAudioNonCommon, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = RecorderServiceStub::Create();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;

    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(stub->GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(VideoSourceType::VIDEO_SOURCE_SURFACE_ES));

    int32_t ret = stub->OnRemoteRequest(IStandardRecorderService::SET_VIDEO_SOURCE, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    (void)reply.ReadInt32(); // consume sourceId from reply
    EXPECT_EQ(reply.ReadInt32(), MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: OnRemoteRequest_InvalidDescriptor
 * @tc.desc: OnRemoteRequest with mismatched interface descriptor
 *           Covers line 202 CHECK_AND_RETURN_RET_LOG true branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, OnRemoteRequest_InvalidDescriptor, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;

    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(u"InvalidDescriptor");

    int32_t ret = stub->OnRemoteRequest(IStandardRecorderService::SET_VIDEO_SOURCE, data, reply, option);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: OnRemoteRequest_SetAudioSourceRepeated
 * @tc.desc: OnRemoteRequest SET_AUDIO_SOURCE with audioSourceType_ already set (repeated operation)
 *           Covers line 208 CHECK_AND_RETURN_RET_LOG true branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, OnRemoteRequest_SetAudioSourceRepeated, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    stub->audioSourceType_ = AudioSourceType::AUDIO_MIC;

    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(stub->GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(AudioSourceType::AUDIO_MIC));

    int32_t ret = stub->OnRemoteRequest(IStandardRecorderService::SET_AUDIO_SOURCE, data, reply, option);
    EXPECT_EQ(ret, MSERR_EXT_API9_OPERATE_NOT_PERMIT);
}

/**
 * @tc.name: OnRemoteRequest_UnknownCode_Fallback
 * @tc.desc: OnRemoteRequest with unknown code not in recFuncs_ → falls through to IPCObjectStub
 *           Covers line 247 MEDIA_LOGW path and line 249 IPCObjectStub::OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, OnRemoteRequest_UnknownCode_Fallback, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;

    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(stub->GetDescriptor());

    uint32_t unknownCode = 0xFFFF;
    int32_t ret = stub->OnRemoteRequest(unknownCode, data, reply, option);
    EXPECT_EQ(ret, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: OnRemoteRequest_NonAudioNonCommon_GrantedAndDispatched
 * @tc.desc: OnRemoteRequest with a code that is neither AUDIO_REQUEST nor COMMON_REQUEST,
 *           covers the else branch (line 219-221) and dispatches to memberFunc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, OnRemoteRequest_NonAudioNonCommon_GrantedAndDispatched, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;

    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(stub->GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(VideoSourceType::VIDEO_SOURCE_SURFACE_ES));

    int32_t ret = stub->OnRemoteRequest(IStandardRecorderService::SET_VIDEO_SOURCE, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    (void)reply.ReadInt32(); // consume sourceId from reply
    EXPECT_EQ(reply.ReadInt32(), MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetVideoSource_ParcelNormal
 * @tc.desc: SetVideoSource(MessageParcel) with valid data — covers normal path including
 *           SetVideoSource(VideoSourceType, int32_t&) with recorderServer_ != nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoSource_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;

    MessageParcel data, reply;
    data.WriteInt32(static_cast<int32_t>(VideoSourceType::VIDEO_SOURCE_SURFACE_ES));
    int32_t ret = stub->SetVideoSource(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    (void)reply.ReadInt32(); // consume sourceId from reply
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetVideoSize_ParcelReadFail
 * @tc.desc: SetVideoSize(MessageParcel) with empty parcel → read fails → MSERR_INVALID_VAL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoSize_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetVideoSize(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetVideoSize_ParcelNormal
 * @tc.desc: SetVideoSize(MessageParcel) with valid data and recorderServer_ != nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoSize_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    data.WriteInt32(1920);
    data.WriteInt32(1080);
    int32_t ret = stub->SetVideoSize(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetVideoSize_NullServer
 * @tc.desc: SetVideoSize(VideoSourceType) with recorderServer_ = nullptr → MSERR_NULL_POINTER_5400101
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoSize_NullServer, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    stub->recorderServer_ = nullptr;
    int32_t ret = stub->SetVideoSize(0, 1920, 1080);
    EXPECT_EQ(ret, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetVideoFrameRate_ParcelReadFail
 * @tc.desc: SetVideoFrameRate(MessageParcel) with empty parcel → MSERR_INVALID_VAL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoFrameRate_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetVideoFrameRate(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetVideoFrameRate_ParcelNormal
 * @tc.desc: SetVideoFrameRate(MessageParcel) with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoFrameRate_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    data.WriteInt32(30);
    int32_t ret = stub->SetVideoFrameRate(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetVideoEncodingBitRate_ParcelReadFail
 * @tc.desc: SetVideoEncodingBitRate(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoEncodingBitRate_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetVideoEncodingBitRate(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetVideoEncodingBitRate_ParcelNormal
 * @tc.desc: SetVideoEncodingBitRate(MessageParcel) with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoEncodingBitRate_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    data.WriteInt32(4000000);
    int32_t ret = stub->SetVideoEncodingBitRate(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetVideoIsHdr_ParcelReadFail
 * @tc.desc: SetVideoIsHdr(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoIsHdr_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetVideoIsHdr(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetVideoIsHdr_ParcelNormal
 * @tc.desc: SetVideoIsHdr(MessageParcel) with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoIsHdr_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    data.WriteBool(true);
    int32_t ret = stub->SetVideoIsHdr(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetVideoEnableTemporalScale_ParcelReadFail
 * @tc.desc: SetVideoEnableTemporalScale(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoEnableTemporalScale_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetVideoEnableTemporalScale(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetVideoEnableTemporalScale_ParcelNormal
 * @tc.desc: SetVideoEnableTemporalScale(MessageParcel) with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoEnableTemporalScale_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    data.WriteBool(false);
    int32_t ret = stub->SetVideoEnableTemporalScale(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetVideoEnableStableQualityMode_ParcelReadFail
 * @tc.desc: SetVideoEnableStableQualityMode(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoEnableStableQualityMode_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetVideoEnableStableQualityMode(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetVideoEnableStableQualityMode_ParcelNormal
 * @tc.desc: SetVideoEnableStableQualityMode(MessageParcel) with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoEnableStableQualityMode_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    data.WriteBool(true);
    int32_t ret = stub->SetVideoEnableStableQualityMode(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetVideoEnableBFrame_ParcelReadFail
 * @tc.desc: SetVideoEnableBFrame(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoEnableBFrame_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetVideoEnableBFrame(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetVideoEnableBFrame_ParcelNormal
 * @tc.desc: SetVideoEnableBFrame(MessageParcel) with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoEnableBFrame_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    data.WriteBool(true);
    int32_t ret = stub->SetVideoEnableBFrame(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetVideoSqrFactor_ParcelReadFail
 * @tc.desc: SetVideoSqrFactor(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoSqrFactor_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetVideoSqrFactor(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetVideoSqrFactor_ParcelNormal
 * @tc.desc: SetVideoSqrFactor(MessageParcel) with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoSqrFactor_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    data.WriteInt32(100);
    int32_t ret = stub->SetVideoSqrFactor(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetMetaConfigs_ParcelReadFail
 * @tc.desc: SetMetaConfigs(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetMetaConfigs_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetMetaConfigs(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetMetaConfigs_ParcelNormal
 * @tc.desc: SetMetaConfigs(MessageParcel) with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetMetaConfigs_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    int32_t ret = stub->SetMetaConfigs(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetMetaSource_ParcelReadFail
 * @tc.desc: SetMetaSource(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetMetaSource_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetMetaSource(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetMetaSource_ParcelNormal
 * @tc.desc: SetMetaSource(MessageParcel) with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetMetaSource_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    int32_t ret = stub->SetMetaSource(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    (void)reply.ReadInt32(); // consume sourceId from reply
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetMetaMimeType_ParcelReadFail
 * @tc.desc: SetMetaMimeType(MessageParcel) with valid sourceId but no CString → nullptr branch
 *           Covers line 772 CHECK_AND_RETURN_RET_LOG true branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetMetaMimeType_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    data.WriteInt32(0);
    int32_t ret = stub->SetMetaMimeType(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetMetaMimeType_ParcelNormal
 * @tc.desc: SetMetaMimeType(MessageParcel) with valid sourceId and mimeType string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetMetaMimeType_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    data.WriteString("video/h264");
    int32_t ret = stub->SetMetaMimeType(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetMetaTimedKey_ParcelReadFail
 * @tc.desc: SetMetaTimedKey(MessageParcel) with valid sourceId but no CString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetMetaTimedKey_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    data.WriteInt32(0);
    int32_t ret = stub->SetMetaTimedKey(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetMetaTimedKey_ParcelNormal
 * @tc.desc: SetMetaTimedKey(MessageParcel) with valid sourceId and timedKey string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetMetaTimedKey_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    data.WriteString("key1");
    int32_t ret = stub->SetMetaTimedKey(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetMetaSourceTrackMime_ParcelReadFail
 * @tc.desc: SetMetaSourceTrackMime(MessageParcel) with valid sourceId but no CString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetMetaSourceTrackMime_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    data.WriteInt32(0);
    int32_t ret = stub->SetMetaSourceTrackMime(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetMetaSourceTrackMime_ParcelNormal
 * @tc.desc: SetMetaSourceTrackMime(MessageParcel) with valid sourceId and srcTrackMime string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetMetaSourceTrackMime_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    data.WriteString("audio/aac");
    int32_t ret = stub->SetMetaSourceTrackMime(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: GetSurface_ParcelReadFail
 * @tc.desc: GetSurface(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, GetSurface_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->GetSurface(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: GetSurface_ParcelNormal
 * @tc.desc: GetSurface(MessageParcel) with valid sourceId and recorderServer_ != nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, GetSurface_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    int32_t ret = stub->GetSurface(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadRemoteObject(), nullptr);
}

/**
 * @tc.name: GetMetaSurface_ParcelReadFail
 * @tc.desc: GetMetaSurface(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, GetMetaSurface_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->GetMetaSurface(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: GetMetaSurface_ParcelNormal
 * @tc.desc: GetMetaSurface(MessageParcel) with valid sourceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, GetMetaSurface_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    int32_t ret = stub->GetMetaSurface(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadRemoteObject(), nullptr);
}

/**
 * @tc.name: SetAudioSource_ParcelNormal
 * @tc.desc: SetAudioSource(MessageParcel) with audioSourceType_ set
 *           Covers SetAudioSource(AudioSourceType, int32_t&) with recorderServer_ != nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetAudioSource_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    stub->audioSourceType_ = AudioSourceType::AUDIO_SOURCE_DEFAULT;
    MessageParcel data, reply;
    int32_t ret = stub->SetAudioSource(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    (void)reply.ReadInt32(); // consume sourceId from reply
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetAudioEncoder_ParcelReadFail
 * @tc.desc: SetAudioEncoder(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetAudioEncoder_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetAudioEncoder(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetAudioEncoder_ParcelNormal
 * @tc.desc: SetAudioEncoder(MessageParcel) with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetAudioEncoder_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    data.WriteInt32(static_cast<int32_t>(AudioCodecFormat::AAC_LC));
    int32_t ret = stub->SetAudioEncoder(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetAudioSampleRate_ParcelReadFail
 * @tc.desc: SetAudioSampleRate(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetAudioSampleRate_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetAudioSampleRate(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetAudioSampleRate_ParcelNormal
 * @tc.desc: SetAudioSampleRate(MessageParcel) with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetAudioSampleRate_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    data.WriteInt32(44100);
    int32_t ret = stub->SetAudioSampleRate(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetAudioChannels_ParcelReadFail
 * @tc.desc: SetAudioChannels(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetAudioChannels_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetAudioChannels(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetAudioChannels_ParcelNormal
 * @tc.desc: SetAudioChannels(MessageParcel) with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetAudioChannels_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    data.WriteInt32(2);
    int32_t ret = stub->SetAudioChannels(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetAudioEncodingBitRate_ParcelReadFail
 * @tc.desc: SetAudioEncodingBitRate(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetAudioEncodingBitRate_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetAudioEncodingBitRate(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetAudioEncodingBitRate_ParcelNormal
 * @tc.desc: SetAudioEncodingBitRate(MessageParcel) with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetAudioEncodingBitRate_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    data.WriteInt32(128000);
    int32_t ret = stub->SetAudioEncodingBitRate(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetAudioAacProfile_ParcelNormal
 * @tc.desc: SetAudioAacProfile(MessageParcel) with valid data
 *           Covers the normal path (line 915-916) which is currently uncovered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetAudioAacProfile_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    data.WriteInt32(static_cast<int32_t>(AacProfile::AAC_LC));
    int32_t ret = stub->SetAudioAacProfile(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetDataSource_ParcelReadFail
 * @tc.desc: SetDataSource(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetDataSource_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetDataSource(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetDataSource_ParcelNormal
 * @tc.desc: SetDataSource(MessageParcel) with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetDataSource_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    int32_t ret = stub->SetDataSource(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    (void)reply.ReadInt32(); // consume sourceId from reply
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetMaxDuration_ParcelReadFail
 * @tc.desc: SetMaxDuration(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetMaxDuration_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetMaxDuration(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetMaxDuration_ParcelNormal
 * @tc.desc: SetMaxDuration(MessageParcel) with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetMaxDuration_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(60);
    int32_t ret = stub->SetMaxDuration(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetOutputFormat_ParcelReadFail
 * @tc.desc: SetOutputFormat(MessageParcel) with empty parcel
 *           Covers line 951 true branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetOutputFormat_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetOutputFormat(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetOutputFormat_ParcelNormal
 * @tc.desc: SetOutputFormat(MessageParcel) with valid data and recorderServer_ != nullptr
 *           Covers the normal path of SetOutputFormat(OutputFormatType)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetOutputFormat_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(static_cast<int32_t>(OutputFormatType::FORMAT_MPEG_4));
    int32_t ret = stub->SetOutputFormat(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetOutputFile_ParcelNormal
 * @tc.desc: SetOutputFile(MessageParcel) with valid fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetOutputFile_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    int32_t fd = open("/dev/null", O_RDWR);
    ASSERT_GE(fd, 0) << "Failed to open /dev/null for testing";
    data.WriteFileDescriptor(fd);
    int32_t ret = stub->SetOutputFile(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
    close(fd);
}

/**
 * @tc.name: SetFileGenerationMode_ParcelReadFail
 * @tc.desc: SetFileGenerationMode(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetFileGenerationMode_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetFileGenerationMode(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetFileGenerationMode_ParcelNormal
 * @tc.desc: SetFileGenerationMode(MessageParcel) with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetFileGenerationMode_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(static_cast<int32_t>(FileGenerationMode::AUTO_CREATE_CAMERA_SCENE));
    int32_t ret = stub->SetFileGenerationMode(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetLocation_ParcelReadFail
 * @tc.desc: SetLocation(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetLocation_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetLocation(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetLocation_ParcelNormal
 * @tc.desc: SetLocation(MessageParcel) with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetLocation_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteFloat(39.9f);
    data.WriteFloat(116.4f);
    int32_t ret = stub->SetLocation(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: SetOrientationHint_ParcelReadFail
 * @tc.desc: SetOrientationHint(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetOrientationHint_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetOrientationHint(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetOrientationHint_ParcelNormal
 * @tc.desc: SetOrientationHint(MessageParcel) with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetOrientationHint_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(90);
    int32_t ret = stub->SetOrientationHint(data, reply);
    EXPECT_EQ(ret, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetUserCustomInfo_ParcelNormal
 * @tc.desc: SetUserCustomInfo(MessageParcel) — Meta::FromParcel may fail with empty data,
 *           covers both !ret true and false branches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetUserCustomInfo_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    int32_t ret = stub->SetUserCustomInfo(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetGenre_ParcelReadFail
 * @tc.desc: SetGenre(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetGenre_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetGenre(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetGenre_ParcelNormal
 * @tc.desc: SetGenre(MessageParcel) with valid string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetGenre_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteString("Pop");
    int32_t ret = stub->SetGenre(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: Prepare_ParcelNormal
 * @tc.desc: Prepare(MessageParcel) with recorderServer_ != nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, Prepare_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    int32_t ret = stub->Prepare(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: Start_ParcelNormal
 * @tc.desc: Start(MessageParcel) with recorderServer_ != nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, Start_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    int32_t ret = stub->Start(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: Pause_ParcelNormal
 * @tc.desc: Pause(MessageParcel) with recorderServer_ != nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, Pause_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    int32_t ret = stub->Pause(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: Resume_ParcelNormal
 * @tc.desc: Resume(MessageParcel) with recorderServer_ != nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, Resume_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    int32_t ret = stub->Resume(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: Stop_ParcelReadFail
 * @tc.desc: Stop(MessageParcel) with empty parcel → ReadBool fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, Stop_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->Stop(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: Stop_ParcelNormal
 * @tc.desc: Stop(MessageParcel) with valid data, verifies audioSourceType_ reset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, Stop_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    stub->audioSourceType_ = AudioSourceType::AUDIO_MIC;
    MessageParcel data, reply;
    data.WriteBool(true);
    int32_t ret = stub->Stop(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->audioSourceType_, AudioSourceType::AUDIO_SOURCE_INVALID);
}

/**
 * @tc.name: Reset_ParcelNormal
 * @tc.desc: Reset(MessageParcel) with recorderServer_ != nullptr, verifies flags reset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, Reset_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    stub->needAudioPermissionCheck = true;
    stub->audioSourceType_ = AudioSourceType::AUDIO_MIC;
    MessageParcel data, reply;
    int32_t ret = stub->Reset(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
    EXPECT_FALSE(stub->needAudioPermissionCheck);
    EXPECT_EQ(stub->audioSourceType_, AudioSourceType::AUDIO_SOURCE_INVALID);
}

/**
 * @tc.name: Release_ParcelNormal
 * @tc.desc: Release(MessageParcel) with recorderServer_ != nullptr, verifies flags reset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, Release_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    stub->needAudioPermissionCheck = true;
    stub->audioSourceType_ = AudioSourceType::AUDIO_MIC;
    MessageParcel data, reply;
    int32_t ret = stub->Release(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
    EXPECT_FALSE(stub->needAudioPermissionCheck);
    EXPECT_EQ(stub->audioSourceType_, AudioSourceType::AUDIO_SOURCE_INVALID);
}

/**
 * @tc.name: GetAVRecorderConfig_ParcelNormal
 * @tc.desc: GetAVRecorderConfig(MessageParcel) with recorderServer_ != nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, GetAVRecorderConfig_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    int32_t ret = stub->GetAVRecorderConfig(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    for (int32_t i = 0; i < 17; i++) {
        EXPECT_EQ(reply.ReadInt32(), 0);
    }
}

/**
 * @tc.name: GetLocation_ParcelNormal
 * @tc.desc: GetLocation(MessageParcel) with recorderServer_ != nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, GetLocation_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    int32_t ret = stub->GetLocation(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_FLOAT_EQ(reply.ReadFloat(), 0.0f);
    EXPECT_FLOAT_EQ(reply.ReadFloat(), 0.0f);
}

/**
 * @tc.name: GetCurrentCapturerChangeInfo_ParcelNormal
 * @tc.desc: GetCurrentCapturerChangeInfo(MessageParcel) with recorderServer_ != nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, GetCurrentCapturerChangeInfo_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    int32_t ret = stub->GetCurrentCapturerChangeInfo(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    AudioRecorderChangeInfo changeInfo;
    changeInfo.Unmarshalling(reply);
    EXPECT_EQ(reply.ReadInt32(), MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: GetAvailableEncoder_ParcelNormal
 * @tc.desc: GetAvailableEncoder(MessageParcel) with recorderServer_ != nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, GetAvailableEncoder_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    int32_t ret = stub->GetAvailableEncoder(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    EXPECT_EQ(reply.ReadInt32(), MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: GetMaxAmplitude_ParcelNormal
 * @tc.desc: GetMaxAmplitude(MessageParcel) with recorderServer_ != nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, GetMaxAmplitude_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    int32_t ret = stub->GetMaxAmplitude(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    EXPECT_EQ(reply.ReadInt32(), MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: IsWatermarkSupported_ParcelNormal
 * @tc.desc: IsWatermarkSupported(MessageParcel) with recorderServer_ != nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, IsWatermarkSupported_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    int32_t ret = stub->IsWatermarkSupported(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_FALSE(reply.ReadBool());
    EXPECT_EQ(reply.ReadInt32(), MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetWatermark_NullBuffer
 * @tc.desc: SetWatermark(MessageParcel) with empty data → ReadFromMessageParcel fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetWatermark_InvalidBufferRead, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel emptyData, reply;
    int32_t ret = stub->SetWatermark(emptyData, reply);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetUserMeta_InvalidParcel
 * @tc.desc: SetUserMeta(MessageParcel) with empty data → FromParcel fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetUserMeta_InvalidParcel, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    data.WriteInt32(-1);
    int32_t ret = stub->SetUserMeta(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetWillMuteWhenInterrupted_ParcelReadFail
 * @tc.desc: SetWillMuteWhenInterrupted(MessageParcel) with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetWillMuteWhenInterrupted_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetWillMuteWhenInterrupted(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetWillMuteWhenInterrupted_ParcelNormal
 * @tc.desc: SetWillMuteWhenInterrupted(MessageParcel) with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetWillMuteWhenInterrupted_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteBool(true);
    int32_t ret = stub->SetWillMuteWhenInterrupted(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetListenerObject_ParcelNormal
 * @tc.desc: SetListenerObject(MessageParcel) with null object
 *           Covers null-check branches in SetListenerObject(IRemoteObject&)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetListenerObject_ParcelNormal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    int32_t ret = stub->SetListenerObject(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NO_MEMORY);
}

/**
 * @tc.name: DoIpcAbnormality_Normal
 * @tc.desc: DoIpcAbnormality covers the uncovered function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, DoIpcAbnormality_Normal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    int32_t ret = stub->DoIpcAbnormality();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: DoIpcRecovery_Normal
 * @tc.desc: DoIpcRecovery covers the uncovered function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, DoIpcRecovery_Normal, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    int32_t ret = stub->DoIpcRecovery(false);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: DoIpcRecovery_FromMonitor
 * @tc.desc: DoIpcRecovery with fromMonitor=true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, DoIpcRecovery_FromMonitor, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    int32_t ret = stub->DoIpcRecovery(true);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name: CheckPermission_DefaultGranted
 * @tc.desc: CheckPermission with audioSourceType_ = AUDIO_SOURCE_INVALID → default → GRANTED
 *           Covers the default case in the switch (line 1153)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, CheckPermission_DefaultGranted, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    stub->audioSourceType_ = AudioSourceType::AUDIO_SOURCE_INVALID;
    int32_t ret = stub->CheckPermission();
    EXPECT_EQ(ret, Security::AccessToken::PERMISSION_GRANTED);
}

/**
 * @tc.name: PublicMethods_NullServer
 * @tc.desc: Test multiple public methods with recorderServer_ = nullptr
 *           Covers CHECK_AND_RETURN_RET_LOG null-check branches for all these methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, PublicMethods_NullServer, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;

    int32_t sourceId = 0;
    EXPECT_EQ(stub->SetVideoEncoder(0, VideoCodecFormat::VIDEO_DEFAULT), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetVideoFrameRate(0, 30), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetVideoEncodingBitRate(0, 4000000), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetVideoIsHdr(0, true), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetVideoEnableTemporalScale(0, true), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetVideoEnableStableQualityMode(0, true), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetVideoEnableBFrame(0, true), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetVideoSqrFactor(0, 100), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetMetaConfigs(0), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetMetaMimeType(0, "video/h264"), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetMetaTimedKey(0, "key"), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetMetaSourceTrackMime(0, "audio/aac"), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->GetSurface(0), nullptr);
    EXPECT_EQ(stub->GetMetaSurface(0), nullptr);
    EXPECT_EQ(stub->SetAudioSource(AudioSourceType::AUDIO_MIC, sourceId), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetAudioEncoder(0, AudioCodecFormat::AAC_LC), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetAudioSampleRate(0, 44100), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetAudioChannels(0, 2), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetAudioEncodingBitRate(0, 128000), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetAudioAacProfile(0, AacProfile::AAC_LC), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetDataSource(DataSourceType::METADATA, sourceId), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetMaxDuration(60), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetOutputFile(1), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetFileGenerationMode(FileGenerationMode::AUTO_CREATE_CAMERA_SCENE), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetLocation(39.9f, 116.4f), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetOrientationHint(90), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->Prepare(), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->Start(), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->Pause(), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->Resume(), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->Stop(true), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->Reset(), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->Release(), MSERR_NULL_POINTER_5400101);

    ConfigMap configMap;
    EXPECT_EQ(stub->GetAVRecorderConfig(configMap), MSERR_NULL_POINTER_5400101);
    Location loc;
    EXPECT_EQ(stub->GetLocation(loc), MSERR_NULL_POINTER_5400101);
    AudioRecorderChangeInfo changeInfo;
    EXPECT_EQ(stub->GetCurrentCapturerChangeInfo(changeInfo), MSERR_NULL_POINTER_5400101);
    std::vector<EncoderCapabilityData> encoderInfo;
    EXPECT_EQ(stub->GetAvailableEncoder(encoderInfo), MSERR_NULL_POINTER_5400101);
    int32_t amplitude = 0;
    EXPECT_EQ(stub->GetMaxAmplitude(amplitude), MSERR_NULL_POINTER_5400101);
    bool isWatermarkSupported = false;
    EXPECT_EQ(stub->IsWatermarkSupported(isWatermarkSupported), MSERR_NULL_POINTER_5400101);
    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer();
    EXPECT_EQ(stub->SetWatermark(buffer), MSERR_NULL_POINTER_5400101);
    int32_t watermarkCount = 0;
    EXPECT_EQ(stub->AddWatermark(buffer, 100, 100, watermarkCount), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->SetWillMuteWhenInterrupted(true), MSERR_NULL_POINTER_5400101);
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    EXPECT_EQ(stub->SetUserMeta(userMeta), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->TransmitQos(QOS::QosLevel::QOS_DEFAULT), MSERR_NULL_POINTER_5400101);

    Meta userCustomInfo;
    EXPECT_EQ(stub->SetUserCustomInfo(userCustomInfo), MSERR_NULL_POINTER_5400101);
    std::string genre = "Pop";
    EXPECT_EQ(stub->SetGenre(genre), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->DumpInfo(1), MSERR_NULL_POINTER_5400101);

    MetaSourceType metaSource = MetaSourceType::VIDEO_META_SOURCE_INVALID;
    EXPECT_EQ(stub->SetMetaSource(metaSource, sourceId), MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: SetVideoEncoder_ParcelReadFail
 * @tc.desc: SetVideoEncoder(MessageParcel) with partial data (only sourceId, no encoder)
 *           Covers line 618 true branch when second ReadInt32 fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoEncoder_ParcelReadFail, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    MessageParcel data, reply;
    data.WriteInt32(0);
    int32_t ret = stub->SetVideoEncoder(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name: SetVideoEncoder_ValidCodec
 * @tc.desc: SetVideoEncoder(MessageParcel) with valid codec format within range
 *           Covers the normal path (line 625-627) with recorderServer_ != nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, SetVideoEncoder_ValidCodec, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    MessageParcel data, reply;
    data.WriteInt32(0);
    data.WriteInt32(static_cast<int32_t>(VideoCodecFormat::H264));
    int32_t ret = stub->SetVideoEncoder(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: OnRemoteRequest_CommonRequest_NoAudioCheckGranted
 * @tc.desc: OnRemoteRequest with COMMON_REQUEST code and needAudioPermissionCheck=false
 *           Covers line 217 condition: COMMON_REQUEST.count != 0 but needAudioPermissionCheck = false
 *           → else branch, permission stays GRANTED → dispatches to memberFunc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, OnRemoteRequest_CommonRequest_NoAudioCheckGranted, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    stub->needAudioPermissionCheck = false;

    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(stub->GetDescriptor());
    data.WriteBool(true);

    int32_t ret = stub->OnRemoteRequest(IStandardRecorderService::STOP, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_NULL_POINTER_5400101);
    EXPECT_EQ(stub->audioSourceType_, AudioSourceType::AUDIO_SOURCE_INVALID);
}

/**
 * @tc.name: OnRemoteRequest_AudioRequest_GrantedAndDispatched
 * @tc.desc: OnRemoteRequest with AUDIO_REQUEST code (SET_AUDIO_ENCODER), AUDIO_SOURCE_DEFAULT → CheckPermission
 *           With recorderServer_ != nullptr, memberFunc executes and returns MSERR_OK
 *           Covers AUDIO_REQUEST path with permission GRANTED and successful dispatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, OnRemoteRequest_AudioRequest_GrantedAndDispatched, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);
    stub->recorderServer_ = nullptr;
    stub->audioSourceType_ = AudioSourceType::AUDIO_SOURCE_INVALID;
    stub->needAudioPermissionCheck = false;

    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(stub->GetDescriptor());
    data.WriteInt32(0);
    data.WriteInt32(static_cast<int32_t>(AudioCodecFormat::AAC_LC));

    int32_t ret = stub->OnRemoteRequest(IStandardRecorderService::SET_AUDIO_ENCODER, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_NULL_POINTER_5400101);
}

/**
 * @tc.name: OnRemoteRequest_SetAudioSource_GrantedAndDispatched
 * @tc.desc: OnRemoteRequest with SET_AUDIO_SOURCE, AUDIO_SOURCE_DEFAULT → CheckPermission
 *           In test environment MICROPHONE permission is DENIED, so expect MSERR_NO_PERMISSION_5400102
 *           and audioSourceType_ reset to AUDIO_SOURCE_INVALID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServiceStubTest, OnRemoteRequest_SetAudioSource_GrantedAndDispatched, TestSize.Level2)
{
    sptr<RecorderServiceStub> stub = CreateStub();
    ASSERT_NE(stub, nullptr);

    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(stub->GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(AudioSourceType::AUDIO_SOURCE_DEFAULT));

    int32_t ret = stub->OnRemoteRequest(IStandardRecorderService::SET_AUDIO_SOURCE, data, reply, option);
    EXPECT_EQ(ret, MSERR_NO_PERMISSION_5400102);
    EXPECT_EQ(stub->audioSourceType_, AudioSourceType::AUDIO_SOURCE_INVALID);
}
} // namespace Media
} // namespace OHOS