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
#ifndef MEDIA_SOURCE_TAIHE_H_
#define MEDIA_SOURCE_TAIHE_H_

#include "ohos.multimedia.media.proj.hpp"
#include "ohos.multimedia.media.impl.hpp"
#include "taihe/runtime.hpp"
#include "media_ani_common.h"
#include "media_source_loader_callback_taihe.h"
#include "nocopyable.h"
#include "loading_request.h"

namespace ANI::Media {
using namespace taihe;
using namespace ohos::multimedia::media;
using namespace OHOS::Media;


class MediaSourceImpl {
public:
    static std::shared_ptr<AVMediaSourceTmp> GetMediaSource(ohos::multimedia::media::weak::MediaSource mediaSource);
    static std::shared_ptr<AVMediaSourceTmp> GetMediaSource(MediaSourceImpl *mediaSourceImpl);
    static std::shared_ptr<MediaSourceLoaderCallback> GetSourceLoader(
        ohos::multimedia::media::weak::MediaSource mediaSource);
    MediaSourceImpl(string_view url, optional_view<map<string, string>> headers);
    MediaSourceImpl(array_view<::ohos::multimedia::media::MediaStream> streams);
    int64_t GetImplPtr();
    void SetMimeType(::ohos::multimedia::media::AVMimeTypes mimeType);
    void SetMediaResourceLoaderDelegate(::ohos::multimedia::media::MediaSourceLoader const& resourceLoader);
private:
    static optional<::ohos::multimedia::media::MediaSource> CreateMediaSourceWithUrl(string_view url,
        optional_view<map<string, string>> headers);

    static optional<::ohos::multimedia::media::MediaSource> CreateMediaSourceWithStreamData(
        array_view<::ohos::multimedia::media::MediaStream> streams);

    std::shared_ptr<AVMediaSourceTmp> mediaSource_ {nullptr};
    std::shared_ptr<MediaSourceLoaderCallback> mediaSourceLoaderCb_ {nullptr};
};
} // namespace ANI::Media
#endif // MEDIA_SOURCE_TAIHE_H_