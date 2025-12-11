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
#include <cerrno>
#include <climits>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <fstream>
#include <sstream>
#include <chrono>

#include "color_space.h"
#include "v1_0/cm_color_space.h"
#include "network_security_config.h"

namespace OHOS {
namespace Media {
class AVMetadataHelperImpl : public AVMetadataHelper, public NoCopyable {
public:
    AVMetadataHelperImpl();
    ~AVMetadataHelperImpl();

    int32_t SetSource(const std::string &uri, int32_t usage) override;
    int32_t SetAVMetadataCaller(AVMetadataCaller caller) override;
    int32_t SetUrlSource(const std::string &uri, const std::map<std::string, std::string> &header) override;
    int32_t SetSource(int32_t fd, int64_t offset, int64_t size, int32_t usage) override;
    int32_t SetSource(const std::shared_ptr<IMediaDataSource> &dataSrc) override;
    int32_t CancelAllFetchFrames() override;
    std::string ResolveMetadata(int32_t key) override;
    std::unordered_map<int32_t, std::string> ResolveMetadata() override;
    std::shared_ptr<Meta> GetAVMetadata() override;
    std::shared_ptr<AVSharedMemory> FetchArtPicture() override;
    std::shared_ptr<PixelMap> FetchFrameAtTime(int64_t timeUs, int32_t option, const PixelMapParams &param) override;
    std::shared_ptr<PixelMap> FetchFrameYuv(int64_t timeUs, int32_t option, const PixelMapParams &param) override;
    int32_t FetchScaledFrameYuvs(const std::vector<int64_t>& timeUs,
                            int32_t option, const PixelMapParams &param) override;
    std::shared_ptr<PixelMap> FetchScaledFrameYuv(int64_t timeUs, int32_t option, const PixelMapParams &param) override;
    std::shared_ptr<PixelMap> ProcessPixelMap(const std::shared_ptr<AVBuffer> &frameBuffer,
                                            const PixelMapParams &param, int32_t scaleMode) override;
    void Release() override;
    int32_t Init();
    int32_t SetHelperCallback(const std::shared_ptr<HelperCallback> &callback) override;
    void SetScene(Scene scene) override;
    int32_t GetTimeByFrameIndex(uint32_t index, uint64_t &time) override;
    int32_t GetFrameIndexByTime(uint64_t time, uint32_t &index) override;
private:
    struct PixelMapInfo {
        int32_t rotation = 0;
        int32_t orientation = 0;
        PixelFormat pixelFormat = PixelFormat::NV12;
        bool isHdr = false;
        int32_t width = 0;
        int32_t height = 0;
        int32_t outputHeight = 0;
        int32_t primaries = 0;
        uint8_t srcRange = 0;
        ColorManager::ColorSpaceName colorSpaceName = ColorManager::ColorSpaceName::NONE;
    };

    std::mutex releaseMutex_;

    static std::string GetLocalTime()
    {
        // time string : "year-month-day hour_minute_second.millisecond", ':' is not supported in windows file name
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        auto tmPtr = std::localtime(&t);
        if (tmPtr == nullptr) {
            return "0000-00-00 00_00_00";
        }
        std::tm tmInfo = *tmPtr;

        std::stringstream ss;
        int millSecondWidth = 3;
        ss << std::put_time(&tmInfo, "%Y-%m-%d %H_%M_%S.") << std::setfill('0')
           << std::setw(millSecondWidth) << ms.count();
        return ss.str();
    }

    void FormatColorSpaceInfo(OHOS::HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceInfo &colorSpaceInfo);
    Status GetColorSpace(sptr<SurfaceBuffer> &surfaceBuffer, PixelMapInfo &pixelMapInfo);
    Status GetColorSpaceWithDefaultValue(sptr<SurfaceBuffer> &surfaceBuffer, PixelMapInfo &pixelMapInfo);

    std::shared_ptr<IAVMetadataHelperService> avMetadataHelperService_ = nullptr;
    int32_t rotation_ = 0;
    bool isDump_ = false;
    bool convertColorSpace_ = true;
    static std::chrono::milliseconds cloneTimestamp;
    static std::chrono::milliseconds batchHandleTimestamp;
    void ReportSceneCode(Scene scene);

    std::shared_ptr<PixelMap> CreatePixelMapYuv(const std::shared_ptr<AVBuffer> &frameBuffer,
                                                PixelMapInfo &pixelMapInfo);
    std::shared_ptr<PixelMap> CreatePixelMapFromAVShareMemory(const std::shared_ptr<AVBuffer> &frameBuffer,
                                                              PixelMapInfo &pixelMapInfo,
                                                              InitializationOptions &options);
    std::shared_ptr<PixelMap> CreatePixelMapFromSurfaceBuffer(sptr<SurfaceBuffer> &mySurfaceBuffer,
                                                              PixelMapInfo &pixelMapInfo);
    void SetPixelMapYuvInfo(sptr<SurfaceBuffer> &surfaceBuffer, std::shared_ptr<PixelMap> pixelMap,
                            PixelMapInfo &pixelMapInfo, bool needModifyStride);
    std::string pixelFormatToString(PixelFormat pixelFormat);
    static void ScalePixelMapByMode(std::shared_ptr<PixelMap> &pixelMap, PixelMapInfo &info,
                                    const PixelMapParams &param, int32_t scaleMode);
    static void ScalePixelMap(std::shared_ptr<PixelMap> &pixelMap, PixelMapInfo &info, const PixelMapParams &param);
    static void ScalePixelMapWithEqualRatio(std::shared_ptr<PixelMap> &pixelMap, PixelMapInfo &info,
                                            const PixelMapParams &param);
    std::shared_ptr<PixelMap> FetchFrameBase(int64_t timeUs, int32_t option,
                                             const PixelMapParams &param, int32_t scaleMode);
    int32_t CopySurfaceBufferToPixelMap(sptr<SurfaceBuffer> &SurfaceBuffer,
                                        std::shared_ptr<PixelMap> pixelMap,
                                        PixelMapInfo &pixelMapInfo);
    int32_t SaveDataToFile(const std::string &fileName, const char *data, const size_t &totalSize);
    void InitDumpFlag();
    int32_t DumpPixelMap(bool isDump, std::shared_ptr<PixelMap> pixelMap, const std::string &fileName);
    int32_t DumpAVBuffer(bool isDump, const std::shared_ptr<AVBuffer> &frameBuffer, const std::string &fileName);
};
} // namespace Media
} // namespace OHOS
#endif // AVMETADATAHELPER_IMPL_H
