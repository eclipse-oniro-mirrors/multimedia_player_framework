/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef SOUNDPOOL_UNIT_TEST_H
#define SOUNDPOOL_UNIT_TEST_H

#include "gtest/gtest.h"
#include "soundpool_mock.h"

namespace OHOS {
namespace Media {
class SoundPoolUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);

protected:
    static const int32_t SOUND_NUM = 4;
    static const int32_t waitTime1 = 1;
    static const int32_t waitTime2 = 2;
    static const int32_t waitTime3 = 3;
    static const int32_t waitTime10 = 10;
    static const int32_t waitTime20 = 20;
    static const int32_t waitTime30 = 30;
    int32_t loadNum_ = 0;
    int32_t playNum_ = 0;
    int32_t soundIDs_[SOUND_NUM];
    int32_t streamIDs_[SOUND_NUM];
    int32_t fds_[SOUND_NUM];
    std::shared_ptr<SoundPoolMock> soundPool_ = nullptr;
    std::shared_ptr<SoundPoolParallelMock> soundPoolParallel_ = nullptr;
    void create(int maxStreams);
    void loadUrl(std::string fileName, int32_t loadNum);
    void loadFd(std::string fileName, int32_t loadNum);
    void functionTest043(std::shared_ptr<SoundPoolMock> soundPool1, std::shared_ptr<SoundPoolMock> soundPool2,
        std::shared_ptr<SoundPoolCallbackTest> cb1, std::shared_ptr<SoundPoolCallbackTest> cb2);
    void functionTest044(std::shared_ptr<SoundPoolMock> soundPool1, std::shared_ptr<SoundPoolMock> soundPool2,
        std::shared_ptr<SoundPoolCallbackTest> cb1, std::shared_ptr<SoundPoolCallbackTest> cb2);
    void functionTest045(std::shared_ptr<SoundPoolMock> soundPool1, std::shared_ptr<SoundPoolMock> soundPool2,
        std::shared_ptr<SoundPoolCallbackTest> cb1, std::shared_ptr<SoundPoolCallbackTest> cb2);

    void loadUrlParallel(std::string fileName, int32_t loadNum);
    void loadFdParallel(std::string fileName, int32_t loadNum);
    void functionTest086(std::shared_ptr<SoundPoolParallelMock> soundPool1,
        std::shared_ptr<SoundPoolParallelMock> soundPool2, std::shared_ptr<SoundPoolCallbackTest> cb1,
        std::shared_ptr<SoundPoolCallbackTest> cb2);
};
} // namespace Media
} // namespace OHOS
#endif