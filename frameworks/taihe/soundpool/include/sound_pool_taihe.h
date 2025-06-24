/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef SOUND_POOL_TAIHE_H
#define SOUND_POOL_TAIHE_H

#include "soundPool.proj.hpp"
#include "soundPool.impl.hpp"
#include "taihe/runtime.hpp"
#include "isoundpool.h"
#include "media_ani_common.h"

namespace ANI {
namespace Media {
using namespace taihe;
using namespace soundPool;
using namespace OHOS::Media;

using RetInfo = std::pair<int32_t, std::string>;

struct SoundPoolAsyncContext;

class SoundPoolImpl {
public:
    SoundPoolImpl(int32_t maxStreams, uintptr_t audioRendererInfo);

    double LoadSync(string_view uri);
    double LoadWithFdSync(double fd, double offset, double length);
    double PlaySync(double soundID, optional_view<PlayParameters> params);
    double PlayWithoutParam(double soundID);
    double PlayWithParam(double soundID, PlayParameters const& params);
    void StopSync(double streamID);
    void UnloadSync(double soundID);
    void ReleaseSync();
    void SetLoopSync(double streamID, double loop);
    void SetPrioritySync(double streamID, double priority);
    void SetVolumeSync(double streamID, double leftVolume, double rightVolume);
    void OnError(callback_view<void(uintptr_t)> callback);
    void OffError();

    void OnPlayFinishedWithStreamId(callback_view<void(double)> callback);
    void OffPlayFinishedWithStreamId();

    void OnLoadComplete(callback_view<void(double)> callback);
    void OffLoadComplete();

    void OnPlayFinished(callback_view<void(uintptr_t)> callback);
    void OffPlayFinished();

    int32_t ParserPlayOption(const PlayParameters &params);
    void SetCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref);
    void CancelCallbackReference(const std::string &callbackName);
    void CancelCallback(std::shared_ptr<ISoundPoolCallback> callback);
    void SignError(int32_t code, const std::string &message, bool del = true);
    void SoundPoolAsyncSignError(int32_t errCode, const std::string &operate,
        const std::string &param, const std::string &add = "");
    static void ParseAudioRendererInfo(ani_env *env, ani_object src,
        OHOS::AudioStandard::AudioRendererInfo &audioRendererInfo);
private:
    bool errFlag = false;
    int32_t errCode = 0;
    std::string errMessage = "";
    bool delFlag = true;
    static int32_t maxStreams;
    static OHOS::AudioStandard::AudioRendererInfo rendererInfo;
    std::shared_ptr<ISoundPool> soundPool_;
    std::shared_ptr<ISoundPoolCallback> callbackTaihe_;
    std::map<std::string, std::shared_ptr<AutoRef>> eventCbMap_;
    PlayParams playParameters_;
    std::string url_ = "";
    int32_t fd_ = 0;
    int64_t offset_ = 0;
    int64_t length_ = 0;
    int32_t soundId_ = 0;
    int32_t streamId_ = 0;
    int32_t loop_ = 0;
    int32_t priority_ = 0;
    float leftVolume_ = 0.0f;
    float rightVolume_ = 0.0f;
};

struct SoundPoolAsyncContext {
    explicit SoundPoolAsyncContext() {}
    ~SoundPoolAsyncContext() = default;
    void SoundPoolAsyncSignError(int32_t errCode, const std::string &operate,
        const std::string &param, const std::string &add = "");
    SoundPoolImpl *taihe = nullptr;
    std::shared_ptr<ISoundPool> soundPool_;
    std::shared_ptr<ISoundPoolCallback> callbackTaihe_;
    std::string url_ = "";
    int32_t fd_ = 0;
    int64_t offset_ = 0;
    int64_t length_ = 0;
    int32_t soundId_ = 0;
    PlayParams playParameters_;
    int32_t streamId_ = 0;
    int32_t loop_ = 0;
    int32_t priority_ = 0;
    float leftVolume_ = 0.0f;
    float rightVolume_ = 0.0f;
};
} // namespace Media
} // namespace ANI
#endif // SOUND_POOL_TAIHE_H