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

#include "media_errors.h"
#include "parallel_stream_manager_test.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

static const int32_t ID_TEST = 1;
static const int32_t NUM_TEST = 0;
static const int32_t DEFAULT_NUM = 10;
void ParallelStreamManagerTest::SetUpTestCase(void) {}
void ParallelStreamManagerTest::TearDownTestCase(void) {}
void ParallelStreamManagerTest::SetUp(void)
{
    int32_t maxStreams = 1;
    AudioStandard::AudioRendererInfo audioRenderInfo;
    testPtr_ = std::make_shared<ParallelStreamManager>(maxStreams, audioRenderInfo);
}
void ParallelStreamManagerTest::TearDown(void)
{
    testPtr_ = nullptr;
}

/**
 * @tc.name  : Test ~ParallelStreamManager
 * @tc.number: ParallelStreamManagerTestDestruct_001
 * @tc.desc  : Test frameWriteCallback_ != nullptr
 */
HWTEST_F(ParallelStreamManagerTest, ParallelStreamManagerTestDestruct_001, TestSize.Level0)
{
    ASSERT_NE(testPtr_, nullptr);
    auto frameWriteCallback = std::make_shared<MockISoundPoolFrameWriteCallback>();
    testPtr_->frameWriteCallback_ = frameWriteCallback;
    EXPECT_NE(testPtr_->frameWriteCallback_, nullptr);
}

/**
 * @tc.name  : Test InitThreadPool
 * @tc.number: ParallelStreamManagerInitThreadPool_001
 * @tc.desc  : Test maxStreams_ < MIN_PLAY_STREAMS_NUMBER
 */
HWTEST_F(ParallelStreamManagerTest, ParallelStreamManagerInitThreadPool_001, TestSize.Level0)
{
    ASSERT_NE(testPtr_, nullptr);
    testPtr_->maxStreams_ = NUM_TEST;
    testPtr_->frameWriteCallback_ = nullptr;
    auto ret = testPtr_->InitThreadPool();
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test RemoveFromWaitingDeque
 * @tc.number: ParallelStreamManagerRemoveFromWaitingDeque_001
 * @tc.desc  : Test it->first != streamId
 */
HWTEST_F(ParallelStreamManagerTest, ParallelStreamManagerRemoveFromWaitingDeque_001, TestSize.Level0)
{
    ASSERT_NE(testPtr_, nullptr);
    int32_t idTest = ID_TEST;
    std::shared_ptr<Stream> testPtr1 = nullptr;
    Format trackFormat;
    int32_t soundID = ID_TEST;
    int32_t streamID = DEFAULT_NUM;
    std::shared_ptr<ThreadPool> streamStopThreadPool;
    std::shared_ptr<Stream> testPtr2 = std::make_shared<Stream>(trackFormat, soundID, streamID, streamStopThreadPool);
    testPtr_->waitingStream_.push_back(std::make_pair(0, testPtr1));
    testPtr_->waitingStream_.push_back(std::make_pair(idTest, testPtr2));
    testPtr_->RemoveFromWaitingDeque(idTest);
    EXPECT_EQ(testPtr_->waitingStream_.size(), 1);
}

/**
 * @tc.name  : Test AddToPlayingDeque
 * @tc.number: ParallelStreamManagerAddToPlayingDeque_001
 * @tc.desc  : Test stream->GetPriority() >= playingStream->GetPriority()
 */
HWTEST_F(ParallelStreamManagerTest, ParallelStreamManagerAddToPlayingDeque_001, TestSize.Level0)
{
    ASSERT_NE(testPtr_, nullptr);
    int32_t streamID1 = ID_TEST;
    Format trackFormat;
    int32_t soundID = ID_TEST;
    int32_t streamID2 = DEFAULT_NUM;
    std::shared_ptr<ThreadPool> streamStopThreadPool;
    std::shared_ptr<Stream> stream = std::make_shared<Stream>(trackFormat, soundID, streamID1, streamStopThreadPool);
    std::shared_ptr<Stream> stream2 = std::make_shared<Stream>(trackFormat, soundID, streamID2, streamStopThreadPool);
    testPtr_->playingStream_.push_back(std::make_pair(1, stream2));
    testPtr_->AddToPlayingDeque(streamID1, stream);
    EXPECT_EQ(testPtr_->playingStream_.size(), 2);
}

/**
 * @tc.name  : Test DoPlay
 * @tc.number: ParallelStreamManagerDoPlay_001
 * @tc.desc  : Test it->first == streamID
 *             Test it->first != streamID
 */
HWTEST_F(ParallelStreamManagerTest, ParallelStreamManagerDoPlay_001, TestSize.Level0)
{
    ASSERT_NE(testPtr_, nullptr);
    int32_t streamID1 = ID_TEST;
    Format trackFormat;
    int32_t soundID = ID_TEST;
    int32_t streamID2 = DEFAULT_NUM;
    std::shared_ptr<ThreadPool> streamStopThreadPool;
    std::shared_ptr<Stream> stream1 = std::make_shared<Stream>(trackFormat, soundID, streamID2, streamStopThreadPool);
    std::shared_ptr<Stream> stream2 = std::make_shared<Stream>(trackFormat, soundID, streamID2, streamStopThreadPool);
    testPtr_->playingStream_.push_back(std::make_pair(0, stream1));
    testPtr_->playingStream_.push_back(std::make_pair(1, stream2));
    auto ret = testPtr_->DoPlay(streamID1);
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/**
 * @tc.name  : Test UnloadStream
 * @tc.number: ParallelStreamManagerUnloadStream_001
 * @tc.desc  : Test it->second->GetSoundID() == soundId
 *             Test it->second->GetSoundID() != soundId
 *             Test it = playingStream_.begin(), it->second->GetSoundID() != soundId
 */
HWTEST_F(ParallelStreamManagerTest, ParallelStreamManagerUnloadStream_001, TestSize.Level0)
{
    ASSERT_NE(testPtr_, nullptr);
    int32_t streamID1 = ID_TEST;
    Format trackFormat;
    int32_t soundID = ID_TEST;
    int32_t streamID2 = DEFAULT_NUM;
    std::shared_ptr<ThreadPool> streamStopThreadPool;
    std::shared_ptr<Stream> stream1 = std::make_shared<Stream>(trackFormat, soundID, streamID2, streamStopThreadPool);
    std::shared_ptr<Stream> stream2 = std::make_shared<Stream>(trackFormat, soundID, streamID2, streamStopThreadPool);
    testPtr_->waitingStream_.push_back(std::make_pair(0, stream1));
    testPtr_->waitingStream_.push_back(std::make_pair(1, stream2));

    std::shared_ptr<Stream> stream3 = std::make_shared<Stream>(trackFormat, soundID, streamID2, streamStopThreadPool);
    std::shared_ptr<Stream> stream4 = std::make_shared<Stream>(trackFormat, soundID, streamID2, streamStopThreadPool);
    testPtr_->playingStream_.push_back(std::make_pair(0, stream3));
    testPtr_->playingStream_.push_back(std::make_pair(1, stream4));
    auto ret = testPtr_->UnloadStream(streamID1);
    EXPECT_EQ(ret, MSERR_OK);
}

/**
 * @tc.name  : Test ReorderStream
 * @tc.number: ParallelStreamManagerReorderStream_001
 * @tc.desc  : Test (left != nullptr && right != nullptr && left->GetPriority() < right->GetPriority()) == true
 */
HWTEST_F(ParallelStreamManagerTest, ParallelStreamManagerReorderStream_001, TestSize.Level0)
{
    ASSERT_NE(testPtr_, nullptr);
    Format trackFormat;
    int32_t soundID = ID_TEST;
    int32_t streamID2 = DEFAULT_NUM;
    std::shared_ptr<ThreadPool> streamStopThreadPool;
    std::shared_ptr<Stream> stream1 = std::make_shared<Stream>(trackFormat, soundID, streamID2, streamStopThreadPool);
    std::shared_ptr<Stream> stream2 = std::make_shared<Stream>(trackFormat, soundID, streamID2, streamStopThreadPool);
    testPtr_->playingStream_.push_back(std::make_pair(0, stream1));
    testPtr_->playingStream_.push_back(std::make_pair(1, stream2));
    testPtr_->ReorderStream();
    EXPECT_EQ(testPtr_->playingStream_.size(), 2);
}

/**
 * @tc.name  : Test SetFrameWriteCallback
 * @tc.number: ParallelStreamManagerSetFrameWriteCallback_001
 * @tc.desc  : Test all
 */
HWTEST_F(ParallelStreamManagerTest, ParallelStreamManagerSetFrameWriteCallback_001, TestSize.Level0)
{
    ASSERT_NE(testPtr_, nullptr);
    auto frameWriteCallback = std::make_shared<MockISoundPoolFrameWriteCallback>();
    std::shared_ptr<ISoundPoolFrameWriteCallback> callback = frameWriteCallback;
    auto ret = testPtr_->SetFrameWriteCallback(callback);
    EXPECT_EQ(ret, MSERR_OK);
}
} // namespace Media
} // namespace OHOS
