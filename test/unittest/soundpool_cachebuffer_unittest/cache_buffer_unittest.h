/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef CACHE_BUFFER_UNITTEST_H
#define CACHE_BUFFER_UNITTEST_H

#include "gtest/gtest.h"
#include "mock/mock_audio_renderer.h"
#include "mock/mock_sound_pool_callback.h"
#include "stream_id_manager.h"


namespace OHOS {
namespace Media {
class CacheBufferUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);

protected:
    Format trackFormat = Format();
    int32_t soundID = 0;
    int32_t streamID = 0;
    std::shared_ptr<ThreadPool> cacheBufferStopThreadPool = nullptr;

    std::shared_ptr<AudioStream> cacheBuffer_;
    std::shared_ptr<StreamIDManager> streamIDManager_;
    std::unique_ptr<MockAudioRenderer> mockAudioRenderer_;
};
} // namespace Media
} // namespace OHOS
#endif // CACHE_BUFFER_UNITTEST_H