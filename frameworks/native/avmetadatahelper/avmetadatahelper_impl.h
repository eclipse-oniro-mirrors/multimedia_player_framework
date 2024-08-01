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
#ifndef AVMETADATAHELPER_IMPL_H
#define AVMETADATAHELPER_IMPL_H

#include "avmetadatahelper.h"
#include "nocopyable.h"
#include "i_avmetadatahelper_service.h"
#include "surface_buffer.h"

namespace OHOS {
namespace Media {
class AVMetadataHelperImpl : public AVMetadataHelper, public NoCopyable {
public:
    AVMetadataHelperImpl();
    ~AVMetadataHelperImpl();

    int32_t SetSource(const std::string &uri, int32_t usage) override;
    int32_t SetSource(int32_t fd, int64_t offset, int64_t size, int32_t usage) override;
    int32_t SetSource(const std::shared_ptr<IMediaDataSource> &dataSrc) override;
    std::string ResolveMetadata(int32_t key) override;
    std::unordered_map<int32_t, std::string> ResolveMetadata() override;
    std::shared_ptr<Meta> GetAVMetadata() override;
    std::shared_ptr<AVSharedMemory> FetchArtPicture() override;
    std::shared_ptr<PixelMap> FetchFrameAtTime(int64_t timeUs, int32_t option, const PixelMapParams &param) override;
    std::shared_ptr<PixelMap> FetchFrameYuv(int64_t timeUs, int32_t option, const PixelMapParams &param) override;
    void Release() override;
    int32_t Init();
    int32_t SetHelperCallback(const std::shared_ptr<HelperCallback> &callback) override;
    void SetScene(Scene scene) override;
    int32_t GetTimeByFrameIndex(uint32_t index, int64_t &time) override;
    int32_t GetFrameIndexByTime(int64_t time, uint32_t &index) override;
private:
    struct PixelMapInfo {
        int32_t rotation = 0;
        PixelFormat pixelFormat = PixelFormat::NV12;
        bool isHdr = false;
    };

    std::shared_ptr<IAVMetadataHelperService> avMetadataHelperService_ = nullptr;
    int32_t rotation_ = 0;
    static std::chrono::milliseconds cloneTimestamp;
    static std::chrono::milliseconds batchHandleTimestamp;
    void ReportSceneCode(Scene scene);

    sptr<SurfaceBuffer> CopySurfaceBuffer(sptr<SurfaceBuffer> &srcSurfaceBuffer);
    std::shared_ptr<PixelMap> CreatePixelMapYuv(const std::shared_ptr<AVBuffer> &frameBuffer,
                                                PixelMapInfo &pixelMapInfo);
    void CopySurfaceBufferInfo(sptr<SurfaceBuffer> &source, sptr<SurfaceBuffer> &dst);
    bool GetSbStaticMetadata(sptr<SurfaceBuffer> &buffer, std::vector<uint8_t> &staticMetadata);
    bool GetSbDynamicMetadata(sptr<SurfaceBuffer> &buffer, std::vector<uint8_t> &dynamicMetadata);
    bool SetSbStaticMetadata(sptr<SurfaceBuffer> &buffer, const std::vector<uint8_t> &staticMetadata);
    bool SetSbDynamicMetadata(sptr<SurfaceBuffer> &buffer, const std::vector<uint8_t> &dynamicMetadata);
    int32_t CopySurfaceBufferPixels(sptr<SurfaceBuffer> &srcSurfaceBuffer, sptr<SurfaceBuffer> &dstSurfaceBuffer);
};
} // namespace Media
} // namespace OHOS
#endif // AVMETADATAHELPER_IMPL_H
