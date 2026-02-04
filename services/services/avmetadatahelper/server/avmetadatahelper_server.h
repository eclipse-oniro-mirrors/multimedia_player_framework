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

#ifndef AVMETADATAHELPER_SERVICE_SERVER_H
#define AVMETADATAHELPER_SERVICE_SERVER_H

#include <mutex>
#include "i_avmetadatahelper_service.h"
#include "i_avmetadatahelper_engine.h"
#include "nocopyable.h"
#include "uri_helper.h"
#include "task_queue.h"
#include <future>

namespace OHOS {
namespace Media {
class AVMetadataHelperServer : public IAVMetadataHelperService, public NoCopyable {
public:
    static std::shared_ptr<IAVMetadataHelperService> Create();
    AVMetadataHelperServer();
    virtual ~AVMetadataHelperServer();

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
    std::shared_ptr<AVBuffer> FetchFrameYuv(int64_t timeUs,
        int32_t option, const OutputConfiguration &param) override;
    int32_t FetchFrameYuvs(const std::vector<int64_t>& timeUsVector,
        int32_t option, const PixelMapParams &param) override;
    int32_t CancelAllFetchFrames() override;
    void Release() override;
    int32_t SetHelperCallback(const std::shared_ptr<HelperCallback> &callback) override;
    int32_t GetTimeByFrameIndex(uint32_t index, uint64_t &time) override;
    int32_t GetFrameIndexByTime(uint64_t time, uint32_t &index) override;

private:
    const std::string &GetStatusDescription(int32_t status);
    void ChangeState(const HelperStates state);
    void NotifyErrorCallback(int32_t code, const std::string msg);
    void NotifyInfoCallback(HelperOnInfoType type, int32_t extra);
    void NotifyPixelCompleteCallback(HelperOnInfoType type,
        const std::shared_ptr<AVBuffer> &reAvbuffer_,
        const FrameInfo &info,
        const PixelMapParams &param);
    int32_t InitEngine(const std::string &uri);
    int32_t CheckSourceByUriHelper();

    int32_t appUid_ = 0;
    int32_t appPid_ = 0;
    enum fetchRes : int32_t {
        FETCH_FAILED = 0,
        FETCH_SUCCEEDED = 1,
        FETCH_CANCELED = 2
    };
    uint32_t appTokenId_ = 0;
    std::string appName_;
    std::shared_ptr<IAVMetadataHelperEngine> avMetadataHelperEngine_ = nullptr;
    std::mutex mutex_;
    std::condition_variable ipcReturnCond_;
    std::atomic<bool> isInterrupted_ = false;
    std::unique_ptr<UriHelper> uriHelper_;
    TaskQueue taskQue_;
    std::shared_ptr<IMediaDataSource> dataSrc_ = nullptr;
    bool isLiveStream_ = false;
    std::atomic<bool> isCanceled_ = false;
    struct ConfigInfo {
        std::atomic<bool> looping = false;
        float leftVolume = INVALID_VALUE;
        float rightVolume = INVALID_VALUE;
        std::string url;
    } config_;
    static constexpr float INVALID_VALUE = 2.0f;

    std::shared_ptr<HelperCallback> helperCb_ = nullptr;
    HelperStates currState_ = HelperStates::HELPER_IDLE;
    std::mutex mutexCb_;
};
} // namespace Media
} // namespace OHOS
#endif // AVMETADATAHELPER_SERVICE_SERVER_H
