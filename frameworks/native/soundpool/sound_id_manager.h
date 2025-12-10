
/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#ifndef SOUND_ID_MANAGER_H
#define SOUND_ID_MANAGER_H

#include <atomic>
#include <deque>
#include <map>
#include <mutex>

#include "isoundpool.h"
#include "sound_parser.h"
#include "thread_pool.h"

namespace OHOS {
namespace Media {
class SoundIDManager {
public:
    SoundIDManager();
    ~SoundIDManager();

    int32_t Load(const std::string &url);
    int32_t Load(int32_t fd, int64_t offset, int64_t length);
    int32_t DoLoad(int32_t soundID);
    int32_t DoParser();

    int32_t Unload(int32_t soundID);

    int32_t SetCallback(const std::shared_ptr<ISoundPoolCallback> &callback);

    std::shared_ptr<SoundParser> GetSoundParserBySoundID(int32_t soundID) const;

    void SetApiVersion(int32_t apiVersion);

private:
    int32_t InitThreadPool();

    std::mutex soundManagerLock_;
    std::shared_ptr<ISoundPoolCallback> callback_ = nullptr;
    int32_t nextSoundID_ = 0;
    std::map<int32_t, std::shared_ptr<SoundParser>> soundParsers_;

    std::atomic<bool> isParsingThreadPoolStarted_;
    std::unique_ptr<ThreadPool> soundParserThreadPool_ = nullptr;

    std::condition_variable queueSpaceValid_;
    std::condition_variable queueDataValid_;
    std::deque<int32_t> soundIDs_;
    bool isQuitQueue_ = false;
    
    int32_t apiVersion_ = 0;
};
} // namespace Media
} // namespace OHOS
#endif // SOUND_ID_MANAGER_H
