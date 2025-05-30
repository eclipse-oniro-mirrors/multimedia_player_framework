/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef AVMETADATAHELPER_SERVICE_CLIENT_H
#define AVMETADATAHELPER_SERVICE_CLIENT_H

#include "i_avmetadatahelper_service.h"
#include "i_standard_avmetadatahelper_service.h"
#include "media_data_source_stub.h"
#include "helper_listener_stub.h"

namespace OHOS {
namespace Media {
class AVMetadataHelperClient : public IAVMetadataHelperService, public NoCopyable {
public:
    static std::shared_ptr<AVMetadataHelperClient> Create(const sptr<IStandardAVMetadataHelperService> &ipcProxy);
    explicit AVMetadataHelperClient(const sptr<IStandardAVMetadataHelperService> &ipcProxy);
    ~AVMetadataHelperClient();

    // IAVMetadataHelperService override
    int32_t SetHelperCallback(const std::shared_ptr<HelperCallback> &callback) override;
    int32_t SetSource(const std::string &uri, int32_t usage) override;
    int32_t SetAVMetadataCaller(AVMetadataCaller caller) override;
    int32_t SetUrlSource(const std::string &uri, const std::map<std::string, std::string> &header) override;
    int32_t SetSource(int32_t fd, int64_t offset, int64_t size, int32_t usage) override;
    int32_t SetSource(const std::shared_ptr<IMediaDataSource> &dataSrc) override;
    std::string ResolveMetadata(int32_t key) override;
    std::unordered_map<int32_t, std::string> ResolveMetadata() override;
    std::shared_ptr<Meta> GetAVMetadata() override;
    std::shared_ptr<AVSharedMemory> FetchArtPicture() override;
    std::shared_ptr<AVSharedMemory> FetchFrameAtTime(int64_t timeUs,
        int32_t option, const OutputConfiguration &param) override;
    int32_t GetTimeByFrameIndex(uint32_t index, uint64_t &time) override;
    int32_t GetFrameIndexByTime(uint64_t time, uint32_t &index) override;
    std::shared_ptr<AVBuffer> FetchFrameYuv(int64_t timeUs,
        int32_t option, const OutputConfiguration &param) override;
    void Release() override;

    // AVMetadataHelperClient
    void MediaServerDied();
private:
    int32_t CreateListenerObject();

    sptr<IStandardAVMetadataHelperService> avMetadataHelperProxy_ = nullptr;
    std::mutex mutex_;
    std::shared_ptr<HelperCallback> callback_ = nullptr;
    sptr<MediaDataSourceStub> dataSrcStub_ = nullptr;
    sptr<HelperListenerStub> listenerStub_ = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif // AVMETADATAHELPER_SERVICE_CLIENT_H
