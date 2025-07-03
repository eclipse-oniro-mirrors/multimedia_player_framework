/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef AUDIO_INFO_H
#define AUDIO_INFO_H

#include <stdint.h>
#include <sys/time.h>

#include <cmath>
#include <limits>
#include <string>
#include <vector>
#include <array>
#include <unistd.h>
#include <unordered_map>

namespace OHOS {
namespace AudioStandard {
enum AudioSamplingRate {
    SAMPLE_RATE_8000 = 8000,
    SAMPLE_RATE_11025 = 11025,
    SAMPLE_RATE_12000 = 12000,
    SAMPLE_RATE_16000 = 16000,
    SAMPLE_RATE_22050 = 22050,
    SAMPLE_RATE_24000 = 24000,
    SAMPLE_RATE_32000 = 32000,
    SAMPLE_RATE_44100 = 44100,
    SAMPLE_RATE_48000 = 48000,
    SAMPLE_RATE_64000 = 64000,
    SAMPLE_RATE_88200 = 88200,
    SAMPLE_RATE_96000 = 96000,
    SAMPLE_RATE_176400 = 176400,
    SAMPLE_RATE_192000 = 192000
};

enum AudioEncodingType {
    ENCODING_INVALID = -1,
    ENCODING_PCM = 0,
    ENCODING_AUDIOVIVID = 1,
    ENCODING_EAC3 = 2
};

enum AudioSampleFormat : uint8_t {
    SAMPLE_U8 = 0,
    SAMPLE_S16LE = 1,
    SAMPLE_S24LE = 2,
    SAMPLE_S32LE = 3,
    SAMPLE_F32LE = 4,
    INVALID_WIDTH = -1
};

enum AudioChannel : uint8_t {
    CHANNEL_UNKNOW = 0,
    MONO = 1,
    STEREO = 2,
    CHANNEL_3 = 3,
    CHANNEL_4 = 4,
    CHANNEL_5 = 5,
    CHANNEL_6 = 6,
    CHANNEL_7 = 7,
    CHANNEL_8 = 8,
    CHANNEL_9 = 9,
    CHANNEL_10 = 10,
    CHANNEL_11 = 11,
    CHANNEL_12 = 12,
    CHANNEL_13 = 13,
    CHANNEL_14 = 14,
    CHANNEL_15 = 15,
    CHANNEL_16 = 16
};

enum StreamUsage {
    STREAM_USAGE_INVALID = -1,
    STREAM_USAGE_UNKNOWN = 0,
    STREAM_USAGE_MEDIA = 1,
    STREAM_USAGE_MUSIC = 1,
    STREAM_USAGE_VOICE_COMMUNICATION = 2,
    STREAM_USAGE_VOICE_ASSISTANT = 3,
    STREAM_USAGE_ALARM = 4,
    STREAM_USAGE_VOICE_MESSAGE = 5,
    STREAM_USAGE_NOTIFICATION_RINGTONE = 6,
    STREAM_USAGE_RINGTONE = 6,
    STREAM_USAGE_NOTIFICATION = 7,
    STREAM_USAGE_ACCESSIBILITY = 8,
    STREAM_USAGE_SYSTEM = 9,
    STREAM_USAGE_MOVIE = 10,
    STREAM_USAGE_GAME = 11,
    STREAM_USAGE_AUDIOBOOK = 12,
    STREAM_USAGE_NAVIGATION = 13,
    STREAM_USAGE_DTMF = 14,
    STREAM_USAGE_ENFORCED_TONE = 15,
    STREAM_USAGE_ULTRASONIC = 16,
    STREAM_USAGE_VIDEO_COMMUNICATION = 17,
    //other StreamUsage
    STREAM_USAGE_RANGING,
    STREAM_USAGE_VOICE_MODEM_COMMUNICATION,
    STREAM_USAGE_VOICE_RINGTONE,
    STREAM_USAGE_VOICE_CALL_ASSISTANT,
    STREAM_USAGE_MAX = STREAM_USAGE_VOICE_CALL_ASSISTANT
};

enum AudioErrors {
    /**
     * Common errors.
     */
    ERROR_INVALID_PARAM = 6800101,
    ERROR_NO_MEMORY     = 6800102,
    ERROR_ILLEGAL_STATE = 6800103,
    ERROR_UNSUPPORTED   = 6800104,
    ERROR_TIMEOUT       = 6800105,
    ERROR_UNSUPPORTED_FORMAT = 6800106,
    /**
     * Audio specific errors.
     */
    ERROR_STREAM_LIMIT  = 6800201,
    /**
     * Default error.
     */
    ERROR_SYSTEM        = 6800301
};

class AudioStreamInfo {
public:
    AudioSamplingRate samplingRate;
    AudioEncodingType encoding = AudioEncodingType::ENCODING_PCM;
    AudioSampleFormat format = AudioSampleFormat::INVALID_WIDTH;
    AudioChannel channels;
    AudioStreamInfo()
    {
    }
};

struct AudioRendererInfo {
    StreamUsage streamUsage = STREAM_USAGE_UNKNOWN;
    int32_t rendererFlags = 0;
};

class Timestamp {
public:
    Timestamp() : framePosition(0)
    {
        time.tv_sec = 0;
        time.tv_nsec = 0;
    }
    virtual ~Timestamp() = default;
    uint32_t framePosition;
    struct timespec time;
    enum Timestampbase {
        /** Monotonically increasing time, excluding the system sleep time */
        MONOTONIC = 0,
        /** Boot time, including the system sleep time */
        BOOTTIME = 1,
        /** Timebase enum size */
        BASESIZE = 2
    };
};

struct BufferDesc {
    uint8_t *buffer;
    size_t bufLength;
    size_t dataLength;
    uint8_t *metaBuffer;
    size_t metaLength;
    uint64_t position;
    uint64_t timeStampInNs;
};
} // namespace AudioStandard
} // namespace OHOS
#endif // AUDIO_INFO_H
