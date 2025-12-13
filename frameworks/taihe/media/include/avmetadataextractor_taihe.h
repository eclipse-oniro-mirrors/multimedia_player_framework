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
#ifndef AVMETADATAEXTRACTOR_TAIHE_H
#define AVMETADATAEXTRACTOR_TAIHE_H

#include "ohos.multimedia.media.proj.hpp"
#include "ohos.multimedia.media.impl.hpp"
#include "taihe/runtime.hpp"
#include "helper_data_source_callback_taihe.h"
#include "avmetadatahelper.h"
#include "audio_info.h"
#include "audio_effect.h"
#include "player.h"
#include "avmetadatahelper_callback_taihe.h"

namespace ANI::Media {
using namespace taihe;
using namespace ohos::multimedia::media;

class AVMetadataExtractorImpl {
public:
    AVMetadataExtractorImpl();
    AVMetadataExtractorImpl(std::shared_ptr<OHOS::Media::AVMetadataHelper> avMetadataHelper);
    optional<AVFileDescriptor> GetFdSrc();
    void SetFdSrc(optional_view<AVFileDescriptor> fdSrc);
    optional<AVDataSrcDescriptor> GetDataSrc();
    void SetDataSrc(optional_view<AVDataSrcDescriptor> dataSrc);
    optional<AVMetadata> FetchMetadataSync();
    optional<ohos::multimedia::image::image::PixelMap> FetchAlbumCoverSync();
    void ReleaseSync();
    void CancelAllFetchFrames();
    int32_t GetFrameIndexByTimeSync(int64_t timeUs);
    int64_t GetTimeByFrameIndexSync(int32_t index);
    void SetUrlSource(::taihe::string_view url, optional_view<map<string, string>> header);
    optional<::ohos::multimedia::image::image::PixelMap> FetchFrameByTimeSync(int64_t timeUs,
        AVImageQueryOptions options, PixelMapParams const& param);
    void FetchFramesByTimes(array_view<int64_t> timeUs, AVImageQueryOptions options, PixelMapParams const& param,
        callback_view<void(::ohos::multimedia::media::FrameInfo const& frameInfo,
        optional_view<uintptr_t> err)> callback);
private:
    std::shared_ptr<OHOS::Media::AVMetadataHelper> helper_;
    std::shared_ptr<OHOS::Media::HelperDataSourceCallback> dataSrcCb_ = nullptr;
    struct OHOS::Media::AVFileDescriptor fileDescriptor_;
    struct DataSrcDescriptor dataSrcDescriptor_;
    OHOS::Media::HelperState state_ { OHOS::Media::HelperState::HELPER_STATE_IDLE };
    uint64_t timeStamp_ = 0;
    uint32_t index_ = 0;
    std::shared_ptr<OHOS::Media::PixelMap> artPicture_ = nullptr;
    void SetMetadataProperty(std::shared_ptr<OHOS::Media::Meta> metadata, AVMetadata &res);
    bool SetPropertyByType(AVMetadata &res, std::shared_ptr<OHOS::Media::Meta> metadata, std::string key);
    void SetDefaultMetadataProperty(AVMetadata &res);
    void SetCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref);
    void setHelper(const std::shared_ptr<OHOS::Media::AVMetadataHelper> &helper);
    std::shared_ptr<OHOS::Media::HelperCallback> helperCb_ = nullptr;
};
} // namespace ANI::Media
#endif // AVMETADATAEXTRACTOR_TAIHE_H