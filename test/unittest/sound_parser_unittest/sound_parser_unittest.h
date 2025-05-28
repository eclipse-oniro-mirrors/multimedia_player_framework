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

#ifndef SOUND_PARSER_UNITTEST_H
#define SOUND_PARSER_UNITTEST_H

#include "gtest/gtest.h"
#include "mock/avdemuxer_impl.h"
#include "mock/avsource_impl.h"
#include "sound_parser.h"
#include <gmock/gmock.h>
#include "avcodec_video_decoder.h"

namespace OHOS {
namespace Media {
class SoundParserUnitTest  : public testing::Test {
public:
    // SetUpTestCase: Called before all test cases
    static void SetUpTestCase(void);
    // TearDownTestCase: Called after all test case
    static void TearDownTestCase(void);
    // SetUp: Called before each test cases
    void SetUp(void);
    // TearDown: Called after each test cases
    void TearDown(void);

    std::shared_ptr<SoundParser> soundParser_;
    std::shared_ptr<SoundDecoderCallback> SoundDecoderCallback_;
};
class MyAVCodecAudioDecoder : public MediaAVCodec::AVCodecAudioDecoder {
public:
    ~MyAVCodecAudioDecoder() = default;
    int32_t Configure(const Format &format)
    {
        return ret;
    }
    int32_t Prepare()
    {
        return 0;
    }
    int32_t Start()
    {
        return 0;
    }
    int32_t Stop()
    {
        return 0;
    }
    int32_t Flush()
    {
        return 0;
    }
    int32_t Reset()
    {
        return ret;
    }
    int32_t Release()
    {
        return 0;
    }
    int32_t QueueInputBuffer(uint32_t index, MediaAVCodec::AVCodecBufferInfo info, MediaAVCodec::AVCodecBufferFlag flag)
    {
        return ret;
    }
    int32_t GetOutputFormat(Format &format)
    {
        return ret;
    }
    int32_t ReleaseOutputBuffer(uint32_t index)
    {
        return ret;
    }
    int32_t SetParameter(const Format &format)
    {
        return 0;
    }
    int32_t SetCallback(const std::shared_ptr<MediaAVCodec::AVCodecCallback> &callback)
    {
        return ret;
    }
    int32_t ret = 1;
};
class MockSoundDecodeListener : public SoundDecoderCallback::SoundDecodeListener {
public:
    MockSoundDecodeListener() = default;
    ~MockSoundDecodeListener() = default;

    void OnSoundDecodeCompleted(const std::shared_ptr<AudioBufferEntry> &fullCacheData) override
    {
        std::cout << "this is mock of OnSoundDecodeCompleted" << std::endl;
    }
    void SetSoundBufferTotalSize(const size_t soundBufferTotalSize) override
    {
        std::cout << "this is mock of SetSoundBufferTotalSize" << std::endl;
    }
};
class MockAVSharedMemory : public AVSharedMemory {
public:
    MOCK_METHOD(uint8_t *, GetBase, (), (override, const));
    MOCK_METHOD(int32_t, GetSize, (), (override, const));
    MOCK_METHOD(uint32_t, GetFlags, (), (override, const));
};
} // namespace Media
} // namespace OHOS
#endif // HIPLAYER_IMPL_UNIT_TEST_H
