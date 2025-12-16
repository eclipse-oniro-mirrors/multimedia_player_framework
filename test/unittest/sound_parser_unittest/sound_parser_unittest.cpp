/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <algorithm>
#include "media_errors.h"
#include "sound_parser_unittest.h"
#include "avsource_impl.h"
#include "parallel_stream_manager.h"
#include "avsharedmemorybase.h"
#include "soundpool_mock.h"

namespace OHOS {
namespace Media {
static const int32_t ID_TEST = 1;
static const int32_t ERR_OK = 0;
using namespace std;
using namespace testing;
using namespace testing::ext;

void SoundParserUnitTest::SetUpTestCase(void)
{
}

void SoundParserUnitTest::TearDownTestCase(void)
{
}

void SoundParserUnitTest::SetUp(void)
{
    soundParser_ = std::make_shared<SoundParser>(1, "testurl");
    soundParser_->demuxer_ = nullptr;
    soundParser_->source_ = nullptr;
}

void SoundParserUnitTest::TearDown(void)
{
    soundParser_ = nullptr;
}

// @tc.name     Test DoParser API
// @tc.number   SoundParser_DoParser_001
// @tc.desc     Test return MSERR_INVALID_VAL
HWTEST_F(SoundParserUnitTest, SoundParser_DoParser_001, TestSize.Level0)
{
    ASSERT_NE(soundParser_, nullptr);
    auto source = std::make_shared<MediaAVCodec::AVSourceImpl>();
    EXPECT_CALL(*(source), GetTrackFormat(_, _)).WillRepeatedly(testing::Return(ID_TEST));
    EXPECT_CALL(*(source), GetSourceFormat(_)).WillRepeatedly(testing::Return(ID_TEST));
    soundParser_->source_ = source;
    std::shared_ptr<AVDemuxerImpl> demuxer = std::make_shared<AVDemuxerImpl>();
    EXPECT_CALL(*(demuxer), SelectTrackByID(_)).WillRepeatedly(testing::Return(ID_TEST));
    soundParser_->demuxer_ = demuxer;
    int32_t ret = soundParser_->DoParser();
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

// @tc.name     Test DoParser API
// @tc.number   SoundParser_DoParser_002
// @tc.desc     Test return MSERR_INVALID_VAL
HWTEST_F(SoundParserUnitTest, SoundParser_DoParser_002, TestSize.Level0)
{
    ASSERT_NE(soundParser_, nullptr);
    auto source = std::make_shared<MediaAVCodec::AVSourceImpl>();
    EXPECT_CALL(*(source), GetTrackFormat(_, _)).WillRepeatedly(testing::Return(ID_TEST));
    EXPECT_CALL(*(source), GetSourceFormat(_)).WillRepeatedly(testing::Return(ID_TEST));
    soundParser_->source_ = source;
    std::shared_ptr<AVDemuxerImpl> demuxer = std::make_shared<AVDemuxerImpl>();
    EXPECT_CALL(*(demuxer), SelectTrackByID(_)).WillRepeatedly(testing::Return(ID_TEST));
    soundParser_->demuxer_ = demuxer;
    std::weak_ptr<ParallelStreamManager> parallelStreamManager;
    soundParser_->callback_ = std::make_shared<ParallelStreamManager::StreamCallBack>(parallelStreamManager);
    int32_t ret = soundParser_->DoParser();
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

// @tc.name     Test DoDemuxer API
// @tc.number   SoundParser_DoDemuxer_001
// @tc.desc     Test return MSERR_OK
HWTEST_F(SoundParserUnitTest, SoundParser_DoDemuxer_001, TestSize.Level0)
{
    ASSERT_NE(soundParser_, nullptr);
    MediaAVCodec::Format trackFormat;
    auto source = std::make_shared<MediaAVCodec::AVSourceImpl>();
    EXPECT_CALL(*(source), GetTrackFormat(_, _)).WillRepeatedly(testing::Return(ID_TEST));
    EXPECT_CALL(*(source), GetSourceFormat(_)).WillRepeatedly(testing::Return(AVCS_ERR_INVALID_OPERATION));
    soundParser_->source_ = source;
    std::shared_ptr<AVDemuxerImpl> demuxer = std::make_shared<AVDemuxerImpl>();
    EXPECT_CALL(*(demuxer), SelectTrackByID(_)).WillRepeatedly(testing::Return(ID_TEST));
    soundParser_->demuxer_ = demuxer;
    MediaAVCodec::Format sourceFormat;
    int32_t ret = soundParser_->source_->GetSourceFormat(sourceFormat);
    EXPECT_EQ(ret, AVCS_ERR_INVALID_OPERATION);
    ret = soundParser_->DoDemuxer(&trackFormat);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

// @tc.name     Test OnError OnInputBufferAvailable SetCallback API
// @tc.number   SoundParser_OnError_001
// @tc.desc     Test OnError all && Test OnInputBufferAvailable demuxer_ = nullptr || audioDec_ = nullptr
HWTEST_F(SoundParserUnitTest, SoundParser_OnError_001, TestSize.Level0)
{
    ASSERT_NE(soundParser_, nullptr);

    // Test OnError all
    int32_t soundID = ID_TEST;
    std::shared_ptr<MediaAVCodec::AVCodecAudioDecoder> audioDec;
    std::shared_ptr<MediaAVCodec::AVDemuxer> demuxer;
    bool isRawFile = true;
    SoundDecoderCallback_ = std::make_shared<SoundDecoderCallback>(soundID, audioDec, demuxer, isRawFile);
    ASSERT_NE(SoundDecoderCallback_, nullptr);
    SoundDecoderCallback_->isRawFile_ = true;
    AVCodecErrorType errorType = AVCodecErrorType::AVCODEC_ERROR_INTERNAL;
    int32_t errorCode = -1;
    SoundDecoderCallback_->OnError(errorType, errorCode);

    // Test OnInputBufferAvailable demuxer_ = nullptr, audioDec_ = nullptr
    uint32_t index = ID_TEST;
    std::shared_ptr<AVSharedMemory> buffer;
    SoundDecoderCallback_->OnInputBufferAvailable(index, buffer);
    std::shared_ptr<ISoundPoolCallback> callback;
    int32_t ret = SoundDecoderCallback_->SetCallback(callback);
    EXPECT_EQ(SoundDecoderCallback_->callback_, nullptr);
    EXPECT_EQ(ret, MSERR_OK);
}

// @tc.name     Test OnInputBufferAvailable API
// @tc.number   SoundParser_OnInputBufferAvailable_002
// @tc.desc     Test buffer != nullptr, isRawFile_ == true, !decodeShouldCompleted_ == true
HWTEST_F(SoundParserUnitTest, SoundParser_OnInputBufferAvailable_002, TestSize.Level0)
{
    ASSERT_NE(soundParser_, nullptr);
    MediaAVCodec::AVCodecBufferFlag bufferFlag = MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_NONE;
    int32_t soundID = ID_TEST;
    std::shared_ptr<MediaAVCodec::AVCodecAudioDecoder> audioDec = std::make_shared<MyAVCodecAudioDecoder>();
    std::shared_ptr<AVDemuxerImpl> demuxer_value = std::make_shared<AVDemuxerImpl>();
    EXPECT_CALL(*(demuxer_value), ReadSample(_, _, _, bufferFlag)).WillRepeatedly(testing::Return(ERR_OK));
    soundParser_->source_ = std::make_shared<MediaAVCodec::AVSourceImpl>();
    std::shared_ptr<MediaAVCodec::AVDemuxer> demuxer = demuxer_value;
    ASSERT_NE(demuxer, nullptr);
    bool isRawFile = true;
    SoundDecoderCallback_ = std::make_shared<SoundDecoderCallback>(soundID, audioDec, demuxer, isRawFile);
    SoundDecoderCallback_->isRawFile_ = true;
    SoundDecoderCallback_->decodeShouldCompleted_ = false;
    ASSERT_NE(SoundDecoderCallback_, nullptr);
    uint32_t index = ID_TEST;
    std::shared_ptr<AVSharedMemory> buffer = std::make_shared<AVSharedMemoryBase>(1, 1, "test");
    SoundDecoderCallback_->OnInputBufferAvailable(index, buffer);
    bool ret = SoundDecoderCallback_->amutex_.try_lock();
    EXPECT_EQ(ret, true);
    if (ret == true) {
        SoundDecoderCallback_->amutex_.unlock();
    }
}

// @tc.name     Test OnInputBufferAvailable API
// @tc.number   SoundParser_OnInputBufferAvailable_003
// @tc.desc     Test (buffer != nullptr && !eosFlag_ && !decodeShouldCompleted_) == true
HWTEST_F(SoundParserUnitTest, SoundParser_OnInputBufferAvailable_003, TestSize.Level0)
{
    ASSERT_NE(soundParser_, nullptr);
    MediaAVCodec::AVCodecBufferFlag bufferFlag = MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_NONE;
    int32_t soundID = ID_TEST;
    std::shared_ptr<MediaAVCodec::AVCodecAudioDecoder> audioDec = std::make_shared<MyAVCodecAudioDecoder>();
    std::shared_ptr<AVDemuxerImpl> demuxer_value = std::make_shared<AVDemuxerImpl>();
    EXPECT_CALL(*(demuxer_value), ReadSample(_, _, _, bufferFlag)).WillRepeatedly(testing::Return(ID_TEST));
    soundParser_->source_ = std::make_shared<MediaAVCodec::AVSourceImpl>();
    std::shared_ptr<MediaAVCodec::AVDemuxer> demuxer = demuxer_value;
    bool isRawFile = true;
    SoundDecoderCallback_ = std::make_shared<SoundDecoderCallback>(soundID, audioDec, demuxer, isRawFile);
    SoundDecoderCallback_->eosFlag_ = false;
    SoundDecoderCallback_->decodeShouldCompleted_ = false;
    ASSERT_NE(SoundDecoderCallback_, nullptr);
    uint32_t index = ID_TEST;
    std::shared_ptr<AVSharedMemory> buffer = std::make_shared<AVSharedMemoryBase>(1, 1, "test");
    SoundDecoderCallback_->OnInputBufferAvailable(index, buffer);
    bool ret = SoundDecoderCallback_->amutex_.try_lock();
    EXPECT_EQ(ret, true);
    if (ret == true) {
        SoundDecoderCallback_->amutex_.unlock();
    }
}

// @tc.name     Test DealBufferRawFile API
// @tc.number   SoundParser_DealBufferRawFile_001
// @tc.desc     Test (demuxer_->ReadSample(0, buffer, sampleInfo, bufferFlag) != AVCS_ERR_OK
HWTEST_F(SoundParserUnitTest, SoundParser_DealBufferRawFile_001, TestSize.Level0)
{
    ASSERT_NE(soundParser_, nullptr);
    MediaAVCodec::AVCodecBufferFlag bufferFlag = MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_NONE;
    int32_t soundID = ID_TEST;
    std::shared_ptr<MediaAVCodec::AVCodecAudioDecoder> audioDec = std::make_shared<MyAVCodecAudioDecoder>();
    std::shared_ptr<AVDemuxerImpl> demuxer_value = std::make_shared<AVDemuxerImpl>();
    EXPECT_CALL(*(demuxer_value), ReadSample(_, _, _, bufferFlag)).WillRepeatedly(testing::Return(ID_TEST));
    soundParser_->source_ = std::make_shared<MediaAVCodec::AVSourceImpl>();
    std::shared_ptr<MediaAVCodec::AVDemuxer> demuxer = demuxer_value;
    bool isRawFile = true;
    SoundDecoderCallback_ = std::make_shared<SoundDecoderCallback>(soundID, audioDec, demuxer, isRawFile);
    SoundDecoderCallback_->eosFlag_ = false;
    SoundDecoderCallback_->decodeShouldCompleted_ = false;
    ASSERT_NE(SoundDecoderCallback_, nullptr);
    uint32_t index = ID_TEST;
    MediaAVCodec::AVCodecBufferInfo sampleInfo;
    std::shared_ptr<AVSharedMemory> buffer = nullptr;
    SoundDecoderCallback_->DealBufferRawFile(bufferFlag, sampleInfo, index, buffer);
    bool ret = SoundDecoderCallback_->demuxer_->ReadSample(0, buffer, sampleInfo, bufferFlag) != AVCS_ERR_OK;
    EXPECT_EQ(ret, true);
}

// @tc.name     Test DealBufferRawFile API
// @tc.number   SoundParser_DealBufferRawFile_002
// @tc.desc     Test decodeShouldCompleted_ == false
//              Test currentSoundBufferSize_ > MAX_SOUND_BUFFER_SIZE
//              Test bufferFlag == AVCODEC_BUFFER_FLAG_EOS
HWTEST_F(SoundParserUnitTest, SoundParser_DealBufferRawFile_002, TestSize.Level0)
{
    ASSERT_NE(soundParser_, nullptr);
    MediaAVCodec::AVCodecBufferFlag bufferFlag = AVCODEC_BUFFER_FLAG_EOS;
    int32_t soundID = ID_TEST;
    std::shared_ptr<MediaAVCodec::AVCodecAudioDecoder> audioDec = std::make_shared<MyAVCodecAudioDecoder>();
    std::shared_ptr<AVDemuxerImpl> demuxer_value = std::make_shared<AVDemuxerImpl>();
    EXPECT_CALL(*(demuxer_value), ReadSample(_, _, _, bufferFlag)).WillRepeatedly(testing::Return(ERR_OK));
    soundParser_->source_ = std::make_shared<MediaAVCodec::AVSourceImpl>();
    std::shared_ptr<MediaAVCodec::AVDemuxer> demuxer = demuxer_value;
    bool isRawFile = true;
    SoundDecoderCallback_ = std::make_shared<SoundDecoderCallback>(soundID, audioDec, demuxer, isRawFile);
    SoundDecoderCallback_->decodeShouldCompleted_ = false;
    ASSERT_NE(SoundDecoderCallback_, nullptr);
    uint32_t index = ID_TEST;
    MediaAVCodec::AVCodecBufferInfo sampleInfo;
    uint8_t testNum = ID_TEST;
    uint8_t *testPtr = &testNum;
    auto mockBuffer = std::make_shared<MockAVSharedMemory>();
    EXPECT_CALL(*(mockBuffer), GetBase()).WillRepeatedly(testing::Return(testPtr));
    std::shared_ptr<AVSharedMemory> buffer = mockBuffer;
    std::shared_ptr<MockSoundDecodeListener> testvalue = std::make_shared<MockSoundDecodeListener>();
    SoundDecoderCallback_->listener_ = testvalue;
    std::shared_ptr<SoundPoolMock> soundPool = std::make_shared<SoundPoolMock>();
    SoundDecoderCallback_->callback_ = std::make_shared<SoundPoolCallbackTest>(soundPool);
    SoundDecoderCallback_->DealBufferRawFile(bufferFlag, sampleInfo, index, buffer);
    EXPECT_EQ(SoundDecoderCallback_->decodeShouldCompleted_, true);
}

// @tc.name     Test DealBufferRawFile API
// @tc.number   SoundParser_DealBufferRawFile_003
// @tc.desc     Test buf != nullptr
//              Test memcpy_s(buf, size, buffer->GetBase(), size) != EOK
HWTEST_F(SoundParserUnitTest, SoundParser_DealBufferRawFile_003, TestSize.Level0)
{
    ASSERT_NE(soundParser_, nullptr);
    MediaAVCodec::AVCodecBufferFlag bufferFlag = AVCODEC_BUFFER_FLAG_EOS;
    int32_t soundID = ID_TEST;
    std::shared_ptr<MediaAVCodec::AVCodecAudioDecoder> audioDec = std::make_shared<MyAVCodecAudioDecoder>();
    std::shared_ptr<AVDemuxerImpl> demuxer_value = std::make_shared<AVDemuxerImpl>();
    EXPECT_CALL(*(demuxer_value), ReadSample(_, _, _, bufferFlag)).WillRepeatedly(testing::Return(ERR_OK));
    soundParser_->source_ = std::make_shared<MediaAVCodec::AVSourceImpl>();
    std::shared_ptr<MediaAVCodec::AVDemuxer> demuxer = demuxer_value;
    bool isRawFile = true;
    SoundDecoderCallback_ = std::make_shared<SoundDecoderCallback>(soundID, audioDec, demuxer, isRawFile);
    SoundDecoderCallback_->decodeShouldCompleted_ = true;
    ASSERT_NE(SoundDecoderCallback_, nullptr);
    uint32_t index = ID_TEST;
    MediaAVCodec::AVCodecBufferInfo sampleInfo;
    sampleInfo.size = 1;
    uint8_t testNum = ID_TEST;
    uint8_t *testPtr = &testNum;
    auto mockBuffer = std::make_shared<MockAVSharedMemory>();
    EXPECT_CALL(*(mockBuffer), GetBase()).WillRepeatedly(testing::Return(testPtr));
    std::shared_ptr<AVSharedMemory> buffer = mockBuffer;
    SoundDecoderCallback_->DealBufferRawFile(bufferFlag, sampleInfo, index, buffer);
    EXPECT_EQ(SoundDecoderCallback_->currentSoundBufferSize_, ID_TEST);
}

// @tc.name     Test OnOutputBufferAvailable API
// @tc.number   SoundParser_OnOutputBufferAvailable_001
// @tc.desc     Test demuxer_ == nullptr, audioDec_ == nullptr
HWTEST_F(SoundParserUnitTest, SoundParser_OnOutputBufferAvailable_001, TestSize.Level0)
{
    ASSERT_NE(soundParser_, nullptr);
    int32_t soundID = ID_TEST;
    std::shared_ptr<MediaAVCodec::AVCodecAudioDecoder> audioDec;
    std::shared_ptr<MediaAVCodec::AVDemuxer> demuxer;
    bool isRawFile = true;
    SoundDecoderCallback_ = std::make_shared<SoundDecoderCallback>(soundID, audioDec, demuxer, isRawFile);
    ASSERT_NE(SoundDecoderCallback_, nullptr);
    MediaAVCodec::AVCodecBufferInfo info;
    MediaAVCodec::AVCodecBufferFlag flag = AVCODEC_BUFFER_FLAG_EOS;
    uint32_t index = ID_TEST;
    std::shared_ptr<AVSharedMemory> buffer = std::make_shared<AVSharedMemoryBase>(1, 1, "test");
    SoundDecoderCallback_->OnOutputBufferAvailable(index, info, flag, buffer);
    bool ret = SoundDecoderCallback_->amutex_.try_lock();
    EXPECT_EQ(ret, true);
    if (ret == true) {
        SoundDecoderCallback_->amutex_.unlock();
    }
}

// @tc.name     Test OnOutputBufferAvailable API
// @tc.number   SoundParser_OnOutputBufferAvailable_002
// @tc.desc     Test isRawFile_ = true
HWTEST_F(SoundParserUnitTest, SoundParser_OnOutputBufferAvailable_002, TestSize.Level0)
{
    ASSERT_NE(soundParser_, nullptr);
    int32_t soundID = ID_TEST;
    std::shared_ptr<MediaAVCodec::AVCodecAudioDecoder> audioDec = std::make_shared<MyAVCodecAudioDecoder>();
    std::shared_ptr<AVDemuxerImpl> demuxer_value = std::make_shared<AVDemuxerImpl>();
    soundParser_->source_ = std::make_shared<MediaAVCodec::AVSourceImpl>();
    std::shared_ptr<MediaAVCodec::AVDemuxer> demuxer = demuxer_value;
    bool isRawFile = true;
    SoundDecoderCallback_ = std::make_shared<SoundDecoderCallback>(soundID, audioDec, demuxer, isRawFile);

    SoundDecoderCallback_->isRawFile_ = true;
    ASSERT_NE(SoundDecoderCallback_, nullptr);
    MediaAVCodec::AVCodecBufferInfo info;
    MediaAVCodec::AVCodecBufferFlag flag = AVCODEC_BUFFER_FLAG_EOS;
    uint32_t index = ID_TEST;
    std::shared_ptr<AVSharedMemory> buffer = std::make_shared<AVSharedMemoryBase>(1, 1, "test");
    SoundDecoderCallback_->OnOutputBufferAvailable(index, info, flag, buffer);
    bool ret = SoundDecoderCallback_->amutex_.try_lock();
    EXPECT_EQ(ret, true);
    if (ret == true) {
        SoundDecoderCallback_->amutex_.unlock();
    }
}
} // namespace Media
} // namespace OHOS
