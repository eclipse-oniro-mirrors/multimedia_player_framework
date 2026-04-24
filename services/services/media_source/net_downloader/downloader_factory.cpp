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

#include "downloader.h"
#include "downloader_impl.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
namespace MediaDownload {

namespace {
constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "DownloaderFactory"};
}

std::shared_ptr<Downloader> DownloaderFactory::CreateDownloader()
{
    MEDIA_LOGI("DownloaderFactory::CreateDownloader");
    
    auto downloader = std::make_shared<DownloaderImpl>();
    if (downloader == nullptr) {
        MEDIA_LOGE("CreateDownloader failed: cannot create DownloaderImpl");
        return nullptr;
    }
    
    MEDIA_LOGI("CreateDownloader success, id=%{public}" PRIu64, downloader->GetDownloaderId());
    return downloader;
}

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS