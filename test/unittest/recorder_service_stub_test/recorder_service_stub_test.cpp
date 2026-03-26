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
#include "media_errors.h"
#include "recorder_service_stub.h"
#include "recorder.h"
#include "i_standard_recorder_service.h"
#include "media_errors.h"
#include "ipc_skeleton.h"
#include "media_log.h"
#include "qos.h"

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
    int32_t ret = recorderServiceStub_->TransmitQos(data, reply);
    EXPECT_EQ(ret, MSERR_OK);
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
    for (auto level : validLevels) {
        MessageParcel data, reply;
        data.WriteInt32(level);
        int32_t ret = recorderServiceStub_->TransmitQos(data, reply);
        EXPECT_EQ(ret, MSERR_OK);
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
    int32_t ret1 = recorderServiceStub_->TransmitQos(data1, reply1);
    EXPECT_EQ(ret1, MSERR_OK);
    MessageParcel data2, reply2;
    int32_t maxLevel = static_cast<int32_t>(QOS::QosLevel::QOS_MAX);
    data2.WriteInt32(maxLevel);
    int32_t ret2 = recorderServiceStub_->TransmitQos(data2, reply2);
    EXPECT_EQ(ret2, MSERR_OK);
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
    data.WriteFileDescriptor(sourceId);
    sptr<RecorderServiceStub> recorderServiceStub_ = RecorderServiceStub::Create();
    int32_t ret = recorderServiceStub_->SetMetaMimeType(data, reply);
    EXPECT_NE(ret, MSERR_OK);
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
    data.WriteFileDescriptor(sourceId);
    sptr<RecorderServiceStub> recorderServiceStub_ = RecorderServiceStub::Create();
    int32_t ret = recorderServiceStub_->SetMetaTimedKey(data, reply);
    EXPECT_NE(ret, MSERR_OK);
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
    data.WriteFileDescriptor(sourceId);
    sptr<RecorderServiceStub> recorderServiceStub_ = RecorderServiceStub::Create();
    int32_t ret = recorderServiceStub_->SetMetaSourceTrackMime(data, reply);
    EXPECT_NE(ret, MSERR_OK);
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
    data.WriteFileDescriptor(sourceId);
    data.WriteFileDescriptor(format);
    sptr<RecorderServiceStub> recorderServiceStub_ = RecorderServiceStub::Create();
    int32_t ret = recorderServiceStub_->SetAudioAacProfile(data, reply);
    EXPECT_NE(ret, MSERR_OK);
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
} // namespace Media
} // namespace OHOS