/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#ifndef AVADS_CONTROLLER_TAIHE_H
#define AVADS_CONTROLLER_TAIHE_H

#include "common_taihe.h"
#include "ohos.multimedia.media.proj.hpp"
#include "ohos.multimedia.media.impl.hpp"
#include "player.h"
#include "taihe/runtime.hpp"
#include "task_queue.h"
#include "media_taihe_utils.h"

namespace ANI::Media {
using namespace taihe;
using namespace ohos::multimedia::media;
using namespace OHOS::Media;
using AdsTaskRet = std::pair<int32_t, std::string>;

class AVPlayerImpl;

class AVAdsControllerImpl {
public:
    AVAdsControllerImpl();
    AVAdsControllerImpl(AVPlayerImpl *player);
    ~AVAdsControllerImpl();
    void SetPlayer(AVPlayerImpl *player);
    AVPlayerImpl *GetPlayer() const;

    string AddAdsMediaSourceSync(::ohos::multimedia::media::weak::MediaSource src, int32_t startMs);
    void RemoveAdsMediaSource(::taihe::string_view id);
    void SkipCurrentAdsMediaSource();
    void DisableAllAdsMediaSource();

    void OnAdsEventListenerLoadingError(callback_view<void(::taihe::string_view, uintptr_t)> callback);
    void OffAdsEventListenerLoadingError(
        optional_view<callback<void(::taihe::string_view, uintptr_t)>> callback);
    void OnAdsListenerAdsStarted(callback_view<void(::taihe::string_view, int64_t)> callback);
    void OffAdsListenerAdsStarted(
        optional_view<callback<void(::taihe::string_view, int64_t)>> callback);
    void OnAdsListenerAdsSkipped(callback_view<void(::taihe::string_view)> callback);
    void OffAdsListenerAdsSkipped(
        optional_view<callback<void(::taihe::string_view)>> callback);
    void OnAdsListenerAdsCompleted(callback_view<void(::taihe::string_view)> callback);
    void OffAdsListenerAdsCompleted(
        optional_view<callback<void(::taihe::string_view)>> callback);

    void Release();

private:
    std::shared_ptr<TaskHandler<AdsTaskRet>> AddAdsMediaSourceTask(
        const std::shared_ptr<AVMediaSource> &mediaSource, int32_t startMs, std::string &outId);
    std::shared_ptr<TaskHandler<AdsTaskRet>> RemoveAdsMediaSourceTask(const std::string &id);
    std::shared_ptr<TaskHandler<AdsTaskRet>> SkipCurrentAdsMediaSourceTask();
    std::shared_ptr<TaskHandler<AdsTaskRet>> DisableAllAdsMediaSourceTask();

    AVPlayerImpl *player_ = nullptr;
    mutable std::mutex mutex_;
};

optional<AVAdsController> CreateAVAdsControllerSync(::ohos::multimedia::media::weak::AVPlayer avplayer);
} // namespace ANI::Media
#endif // AVADS_CONTROLLER_TAIHE_H
