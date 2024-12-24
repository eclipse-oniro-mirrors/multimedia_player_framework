/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

 /**
 * @addtogroup AVRecorder
 * @{
 *
 * @brief Provides APIs of request capability for Recorder.
 *
 * @Syscap SystemCapability.Multimedia.Media.AVRecorder
 * @since 14
 * @version 1.0
 */
 
/**
 * @file avrecorder_base.h
 *
 * @brief Defines the structure and enumeration for Media AVRecorder.
 *
 * @kit MediaKit
 * @library libavrecorder.so
 * @since 14
 * @version 1.0
 */
 
#ifndef MULTIMEDIA_PLAYER_FRAMEWORK_NATIVE_AVRECORDER_BASE_H
#define MULTIMEDIA_PLAYER_FRAMEWORK_NATIVE_AVRECORDER_BASE_H

#include <string>
#include <stdint.h>
#include "media_asset_base_capi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialization of avrecorder
 * @syscap SystemCapability.Multimedia.Media.AVRecorder
 * @since 14
 * @version 1.0
 */
typedef struct OH_AVRecorder OH_AVRecorder;

/**
 * @brief audio source type for recorder
 * @syscap SystemCapability.Multimedia.Media.AVRecorder
 * @since 14
 * @version 1.0
 */
typedef enum OH_AVRecorder_AudioSourceType {
    /* Default audio source type. */
    DEFAULT = 0,
    /* Source type mic. */
    MIC = 1,
    /* Source type Voice recognition. */
    VOICE_RECOGNITION = 2,
    /* Source type Voice communication. */
    VOICE_COMMUNICATION = 7,
    /* Source type Voice message. */
    VOICE_MESSAGE = 10,
    /* Source type Camcorder. */
    CAMCORDER = 13,
} OH_AVRecorder_AudioSourceType;

/**
 * @brief video source type for recorder
 * @syscap SystemCapability.Multimedia.Media.AVRecorder
 * @since 14
 * @version 1.0
 */
typedef enum OH_AVRecorder_VideoSourceType {
    /* Surface raw data. */
    SURFACE_YUV = 0,
    /* Surface ES data. */
    SURFACE_ES = 1,
} OH_AVRecorder_VideoSourceType;

/**
 * @brief Enumerates Codec MIME types
 * @syscap SystemCapability.Multimedia.Media.AVRecorder
 * @since 14
 * @version 1.0
 */
typedef enum OH_AVRecorder_CodecMimeType {
    /* H.264 codec MIME type. */
    VIDEO_AVC = 2,
    /* AAC codec MIME type. */
    AUDIO_AAC = 3,
    /* mp3 codec MIME type. */
    AUDIO_MP3 = 4,
    /* G711-mulaw codec MIME type. */
    AUDIO_G711MU = 5,
    /* MPEG4 codec MIME type. */
    VIDEO_MPEG4 = 6,
    /* H.265 codec MIME type. */
    VIDEO_HEVC = 8,
} OH_AVRecorder_CodecMimeType;

/**
 * @brief Enumerates container format type(The abbreviation for 'container format type' is CFT)
 * @syscap SystemCapability.Multimedia.Media.AVRecorder
 * @since 14
 * @version 1.0
 */
typedef enum OH_AVRecorder_ContainerFormatType {
    /* A video container format type mp4. */
    CFT_MPEG_4 = 2,
    /* A audio container format type m4a. */
    CFT_MPEG_4A = 6,
    /* A audio container format type mp3. */
    CFT_MP3 = 9,
    /* A audio container format type wav. */
    CFT_WAV = 10,
} OH_AVRecorder_ContainerFormatType;

/**
 * @brief Recorder States
 * @syscap SystemCapability.Multimedia.Media.AVRecorder
 * @since 14
 * @version 1.0
 */
typedef enum OH_AVRecorder_State {
    /* idle states */
    IDLE = 0,
    /* prepared states */
    PREPARED = 1,
    /* started states */
    STARTED = 2,
    /* paused states */
    PAUSED = 3,
    /* stopped states */
    STOPPED = 4,
    /* released states */
    RELEASED = 5,
    /* error states */
    ERROR = 6,
} OH_AVRecorder_State;

/**
 * @brief reason of recorder state change
 * @syscap SystemCapability.Multimedia.Media.AVRecorder
 * @since 14
 * @version 1.0
 */
typedef enum OH_AVRecorder_StateChangeReason {
    /* State changed by user operation */
    USER = 0,
    /* State changed by background action */
    BACKGROUND = 1,
} OH_AVRecorder_StateChangeReason;

/**
 * @brief mode of creating recorder file
 * @syscap SystemCapability.Multimedia.Media.AVRecorder
 * @since 14
 * @version 1.0
 */
typedef enum OH_AVRecorder_FileGenerationMode {
    /* Application Creation */
    APP_CREATE = 0,
    /* System Creation. Valid only in camera scene */
    AUTO_CREATE_CAMERA_SCENE = 1,
} OH_AVRecorder_FileGenerationMode;

/**
 * @brief Provides the media recorder profile definitions
 * @syscap SystemCapability.Multimedia.Media.AVRecorder
 * @since 14
 * @version 1.0
 */
typedef struct OH_AVRecorder_Profile {
    /* Indicates the audio bitrate */
    int32_t audioBitrate;
    /* Indicates the number of audio channels */
    int32_t audioChannels;
    /* Indicates the audio encoding format */
    OH_AVRecorder_CodecMimeType audioCodec;
    /* Indicates the audio sampling rate */
    int32_t audioSampleRate;
    /* Indicates the output file format */
    OH_AVRecorder_ContainerFormatType fileFormat;
    /* Indicates the video bitrate */
    int32_t videoBitrate;
    /* Indicates the video encoding format */
    OH_AVRecorder_CodecMimeType videoCodec;
    /* Indicates the video width */
    int32_t videoFrameWidth;
    /* Indicates the video height */
    int32_t videoFrameHeight;
    /* Indicates the video frame rate */
    int32_t videoFrameRate;
    /* Whether to record HDR video */
    bool isHdr;
    /* Whether to encode the video in temporal scale mode */
    bool enableTemporalScale;
} OH_AVRecorder_Profile;

/**
 * @brief Provides the geographical location definitions for media resources
 * @syscap SystemCapability.Multimedia.Media.AVRecorder
 * @since 14
 * @version 1.0
 */
typedef struct OH_AVRecorder_Location {
    /* Latitude */
    float latitude;
    /* Longitude */
    float longitude;
} OH_AVRecorder_Location;

/**
 * @brief define the basic template of metadata
 * @syscap SystemCapability.Multimedia.Media.AVRecorder
 * @since 14
 * @version 1.0
 */
typedef struct OH_AVRecorder_MetadataTemplate {
    /* key value of the matadata */
    char *key;
    /* contents of the matadata */
    char *value;
} OH_AVRecorder_MetadataTemplate;

/**
 * @brief Provides the container definition for media data
 * @syscap SystemCapability.Multimedia.Media.AVRecorder
 * @since 14
 * @version 1.0
 */
typedef struct OH_AVRecorder_Metadata {
    /* The metadata to retrieve the content type or genre of the data source */
    char *genre;
    /* The metadata to retrieve the information about the video orientation */
    char *videoOrientation;
    /* The geographical location info of the video */
    OH_AVRecorder_Location location;
    /* Custom parameter key-value map read from moov.meta.list */
    OH_AVRecorder_MetadataTemplate customInfo;
} OH_AVRecorder_Metadata;

/**
 * @brief Provides the media recorder configuration definitions
 * @syscap SystemCapability.Multimedia.Media.AVRecorder
 * @since 14
 * @version 1.0
 */
typedef struct OH_AVRecorder_Config {
    /* Indicates the recording audio source type */
    OH_AVRecorder_AudioSourceType audioSourceType;
    /* Indicates the recording video source type */
    OH_AVRecorder_VideoSourceType videoSourceType;
    /* Contains the audio and video encoding profile settings */
    OH_AVRecorder_Profile profile;
    /* Defines the file URL */
    char *url;
    /* Specifies the file generation mode for recording output */
    OH_AVRecorder_FileGenerationMode fileGenerationMode;
    /* Contains additional metadata for the recorded media */
    OH_AVRecorder_Metadata metadata;
} OH_AVRecorder_Config;

/**
 * @brief Provides Range with lower and upper limit
 * @syscap SystemCapability.Multimedia.Media.AVRecorder
 * @since 14
 * @version 1.0
 */
typedef struct OH_AVRecorder_Range {
    /* lower limit of the range */
    int32_t min;
    /* upper limit of the range */
    int32_t max;
} OH_AVRecorder_Range;

/**
 * @brief Provides encoder info
 * @syscap SystemCapability.Multimedia.Media.AVRecorder
 * @since 14
 * @version 1.0
 */
typedef struct OH_AVRecorder_EncoderInfo {
    /* encoder format MIME */
    OH_AVRecorder_CodecMimeType mimeType;
    /* encoder type, audio or video */
    char *type;
    /* audio or video encoder bitRate range */
    OH_AVRecorder_Range bitRate;
    /* video encoder frame rate range */
    OH_AVRecorder_Range frameRate;
    /* video encoder width range */
    OH_AVRecorder_Range width;
    /* video encoder height range */
    OH_AVRecorder_Range height;
    /* audio encoder channel range */
    OH_AVRecorder_Range channels;
    /* audio encoder sample rate collection */
    int32_t *sampleRate;
    /* length of sampleRate list */
    int32_t sampleRateLen;
} OH_AVRecorder_EncoderInfo;

/**
 * @brief Called when the state changed of current recording.
 * @syscap SystemCapability.Multimedia.Media.AVRecorder
 * @param recorder The pointer to an OH_AVRecorder instance.
 * @param state Indicates the recorder state. For details, see {@link OH_AVRecorder_State}.
 * @param reason for recorder state change. For details, see {@link OH_AVRecorder_StateChangeReason}.
 * @param userData Pointer to user specific data.
 * @since 14
 * @version 1.0
 */
typedef void (*OH_AVRecorder_OnStateChange)(OH_AVRecorder *recorder,
    OH_AVRecorder_State state, OH_AVRecorder_StateChangeReason reason, void *userData);

/**
 * @brief Called when an error occurred during recording
 * @syscap SystemCapability.Multimedia.Media.AVRecorder
 * @param recorder Pointer to an OH_AVRecorder instance.
 * @param errorCode Error code.
 * @param errorMsg Error message.
 * @param userData Pointer to user specific data.
 * @since 14
 * @version 1.0
 */
typedef void (*OH_AVRecorder_OnError)(OH_AVRecorder *recorder, int32_t errorCode, const char *errorMsg,
    void *userData);

/**
 * @brief Called when current recording is finished in OH_AVRecorder_FileGenerationMode.AUTO_CREATE_CAMERA_SCENE
 * @syscap SystemCapability.Multimedia.Media.AVRecorder
 * @param recorder Pointer to an OH_AVRecorder instance.
 * @param asset Error code.
 * @param userData Pointer to user specific data.
 * @since 14
 * @version 1.0
 */
typedef void (*OH_AVRecorder_OnUri)(OH_AVRecorder *recorder, OH_MediaAsset *asset, void *userData);

#ifdef __cplusplus
}
#endif

#endif // MULTIMEDIA_PLAYER_FRAMEWORK_NATIVE_AVRECORDER_BASE_H