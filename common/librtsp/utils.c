/*************************************************************************
	> File Name: utils.c
	> Author: bxq
	> Mail: 544177215@qq.com
	> Created Time: Sunday, May 22, 2016 PM09:35:22 CST
 ************************************************************************/

#include <string.h>
#include <limits.h>
#include "comm.h"
#include "utils.h"

/*****************************************************************************
* b64_encode: Stolen from VLC's http.c.
* Simplified by Michael.
* Fixed edge cases and made it work from data (vs. strings) by Ryan.
*****************************************************************************/
char *base64_encode (char *out, int out_size, const uint8_t *in, int in_size)
{
	static const char b64[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	char *ret, *dst;
	unsigned i_bits = 0;
	int i_shift = 0;
	int bytes_remaining = in_size;

#define __BASE64_SIZE(x)  (((x)+2) / 3 * 4 + 1)
#define __RB32(x)				      \
	(((uint32_t)((const uint8_t*)(x))[0] << 24) | \
		   (((const uint8_t*)(x))[1] << 16) | \
		   (((const uint8_t*)(x))[2] <<  8) | \
		   ((const uint8_t*)(x))[3])

	if (in_size >= UINT_MAX / 4 ||
		out_size < __BASE64_SIZE(in_size))
		return NULL;
	ret = dst = out;
	while (bytes_remaining > 3) {
		i_bits = __RB32(in);
		in += 3; bytes_remaining -= 3;
		*dst++ = b64[ i_bits>>26		];
		*dst++ = b64[(i_bits>>20) & 0x3F];
		*dst++ = b64[(i_bits>>14) & 0x3F];
		*dst++ = b64[(i_bits>>8 ) & 0x3F];
	}
	i_bits = 0;
	while (bytes_remaining) {
		i_bits = (i_bits << 8) + *in++;
		bytes_remaining--;
		i_shift += 8;
	}
	while (i_shift > 0) {
		*dst++ = b64[(i_bits << 6 >> i_shift) & 0x3f];
		i_shift -= 6;
	}
	while ((dst - ret) & 3)
		*dst++ = '=';
	*dst = '\0';

	return ret;
}

const uint8_t *rtsp_find_h264_h265_nalu (const uint8_t *buff, int len, int *size)
{
	const uint8_t *s = NULL;
    const uint8_t *ptr = buff;
	while (len >= 3) {
		if (ptr[0] == 0 && ptr[1] == 0 && ptr[2] == 1) {
            //found start code 001
            if (ptr > buff && *(ptr-1) == 0) {
                //is 0001
                ptr --;
                len ++;
            }
			if (!s) {
				if (len < 4)
					return NULL;
				s = ptr;
			} else {
				*size = (ptr - s);
				return s;
			}
			ptr += 3;
			len -= 3;
			continue;
		}
		ptr ++;
		len --;
	}
	if (!s)
		return NULL;
	*size = (ptr - s + len);
	return s;
}

const uint8_t *rtsp_find_aac_adts (const uint8_t *buff, int len, int *size)
{
	const uint8_t *s = buff;
	while (len > 2) {
		if (s[0] == 0xff && (s[1] & 0xf0) == 0xf0) {
			break;
		}
		buff ++;
		len --;
	}

	if (len <= 2)
		return NULL;

	//aac_frame_length
	*size = 0;
	*size |= (s[3] & 3) << 11;
	*size |= (s[4] << 3);
	*size |= (s[5] >> 5);

	if (*size > len)
		return NULL;

	return s;
}

int rtsp_codec_data_parse_from_user_h264 (const uint8_t *codec_data, int data_len, struct codec_data_h264 *pst_codec_data)
{
	const uint8_t *s = codec_data;
	int len = data_len;
	int ret = 0;

	while (len > 3) {
		if (pst_codec_data->sps_len > 0 && pst_codec_data->pps_len > 0) {
			break;
		}

		int size = 0;
		const uint8_t *frame = rtsp_find_h264_h265_nalu(s, len, &size);
		if (!frame) {
			break;
		}

		len = len - (frame - s + size);
		s = frame + size;

		if (frame[2] == 0) {
			frame += 4; //drop 0001
			size -= 4;
		} else {
			frame += 3; //drop 001
			size -= 3;
		}

		uint8_t type = frame[0] & 0x1f;
		if (type == 7) {
			dbg("sps %d\n", size);
			if (size > (int)sizeof(pst_codec_data->sps))
				size = sizeof(pst_codec_data->sps);
			memcpy(pst_codec_data->sps, frame, size);
			pst_codec_data->sps_len = size;
			ret ++;
		}
		if (type == 8) {
			dbg("pps %d\n", size);
			if (size > (int)sizeof(pst_codec_data->pps))
				size = sizeof(pst_codec_data->pps);
			memcpy(pst_codec_data->pps, frame, size);
			pst_codec_data->pps_len = size;
			ret ++;
		}
	}

	return (ret >= 2 ? 1 : 0);
}

int rtsp_codec_data_parse_from_user_h265 (const uint8_t *codec_data, int data_len, struct codec_data_h265 *pst_codec_data)
{
	const uint8_t *s = codec_data;
	int len = data_len;
	int ret = 0;

	while (len > 3) {
		if (pst_codec_data->vps_len > 0 && pst_codec_data->sps_len > 0 && pst_codec_data->pps_len > 0) {
			break;
		}

		int size = 0;
		const uint8_t *frame = rtsp_find_h264_h265_nalu(s, len, &size);
		if (!frame) {
			break;
		}

		len = len - (frame - s + size);
		s = frame + size;

		if (frame[2] == 0) {
			frame += 4; //drop 0001
			size -= 4;
		} else {
			frame += 3; //drop 001
			size -= 3;
		}

		uint8_t type = (frame[0] >> 1) & 0x3f;
		if (type == 32) {
			dbg("vps %d\n", size);
			if (size > (int)sizeof(pst_codec_data->vps))
				size = sizeof(pst_codec_data->vps);
			memcpy(pst_codec_data->vps, frame, size);
			pst_codec_data->vps_len = size;
			ret ++;
		}
		if (type == 33) {
			dbg("sps %d\n", size);
			if (size > (int)sizeof(pst_codec_data->sps))
				size = sizeof(pst_codec_data->sps);
			memcpy(pst_codec_data->sps, frame, size);
			pst_codec_data->sps_len = size;
			ret ++;
		}
		if (type == 34) {
			dbg("pps %d\n", size);
			if (size > (int)sizeof(pst_codec_data->pps))
				size = sizeof(pst_codec_data->pps);
			memcpy(pst_codec_data->pps, frame, size);
			pst_codec_data->pps_len = size;
			ret ++;
		}
	}

	return (ret >= 3 ? 1 : 0);
}

int rtsp_codec_data_parse_from_user_g726 (const uint8_t *codec_data, int data_len, struct codec_data_g726 *pst_codec_data)
{
	int bit_rate;

	if (data_len != sizeof(bit_rate)) {
		err("bit rate invalid\n");
		return -1;
	}

	memcpy(&bit_rate, codec_data, sizeof(bit_rate));

	switch (bit_rate) {
	case 16000:
	case 24000:
	case 32000:
	case 40000:
		break;
	default:
		err("bit rate invalid\n");
		return -1;
	}

	pst_codec_data->bit_rate = bit_rate;
	return 1;
}

int rtsp_codec_data_parse_from_user_aac (const uint8_t *codec_data, int data_len, struct codec_data_aac *pst_codec_data)
{
	const uint32_t sample_rate_tbl[16] = {96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350, 0, 0, 0};
	if (data_len != 2) {
		err("audio specific config invalid\n");
		return -1;
	}

	int sample_rate_index = ((codec_data[0] & 0x7) << 1) | (codec_data[1] >> 7);
	int channels = (codec_data[1] >> 3) & 0x0f;

	if (sample_rate_index > 12 || channels > 7) {
		err("audio specific config invalid\n");
		return -1;
	}

	memcpy(pst_codec_data->audio_specific_config, codec_data, data_len);
	pst_codec_data->audio_specific_config_len = data_len;
	pst_codec_data->sample_rate = sample_rate_tbl[sample_rate_index];
	pst_codec_data->channels = (channels == 7) ? 8 : channels;
		dbg("config=%02X%02X sample_rate=%d channels=%d\n",
		pst_codec_data->audio_specific_config[0], pst_codec_data->audio_specific_config[1],
		sample_rate_tbl[sample_rate_index], channels);

	return 1;
}

int rtsp_codec_data_parse_from_frame_h264 (const uint8_t *frame, int len, struct codec_data_h264 *pst_codec_data)
{
	return rtsp_codec_data_parse_from_user_h264(frame, len, pst_codec_data);
}

int rtsp_codec_data_parse_from_frame_h265 (const uint8_t *frame, int len, struct codec_data_h265 *pst_codec_data)
{
	return rtsp_codec_data_parse_from_user_h265(frame, len, pst_codec_data);
}

int rtsp_codec_data_parse_from_frame_aac (const uint8_t *frame, int len, struct codec_data_aac *pst_codec_data)
{
	const uint32_t sample_rate_tbl[16] = {96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350, 0, 0, 0};
	int size = 0;

	if (pst_codec_data->audio_specific_config_len > 0)
		return 0;

	frame = rtsp_find_aac_adts(frame, len, &size);
	if (!frame) {
		err("find adts header failed\n");
		return -1;
	}

	int profile = frame[2] >> 6;
	int sample_rate_index = (frame[2] >> 2) & 0x0f;
	int channels = ((frame[2] & 0x1) << 1) | (frame[3] >> 6);

	if (sample_rate_index > 12 || channels > 7) {
		err("audio specific config invalid\n");
		return -1;
	}

	pst_codec_data->audio_specific_config[0] = ((profile + 1) << 3) | ((sample_rate_index >> 1) & 0x7);
	pst_codec_data->audio_specific_config[1] = ((sample_rate_index & 0x1) << 7) | (channels << 3);
	pst_codec_data->audio_specific_config_len = 2;
	pst_codec_data->sample_rate = sample_rate_tbl[sample_rate_index];
	pst_codec_data->channels = (channels == 7) ? 8 : channels;
	dbg("config=%02X%02X sample_rate=%d channels=%d\n",
		pst_codec_data->audio_specific_config[0], pst_codec_data->audio_specific_config[1],
		sample_rate_tbl[sample_rate_index], channels);

	return 1;
}

int rtsp_build_sdp_media_attr_h264 (int pt, int sample_rate, const struct codec_data_h264 *pst_codec_data, char *sdpbuf, int maxlen)
{
	char *p = sdpbuf;
	int remaining_len = maxlen;
	int written_len;

	written_len = snprintf(p, remaining_len, "m=video 0 RTP/AVP %d\r\n", pt);
	if (written_len < 0 || written_len >= remaining_len) return -1;
	p += written_len;
	remaining_len -= written_len;

	written_len = snprintf(p, remaining_len, "a=rtpmap:%d H264/%d\r\n", pt, sample_rate);
	if (written_len < 0 || written_len >= remaining_len) return -1;
	p += written_len;
	remaining_len -= written_len;

	if (pst_codec_data->sps_len > 0 && pst_codec_data->pps_len > 0) {
		const uint8_t *sps = pst_codec_data->sps;
		const uint8_t *pps = pst_codec_data->pps;
		int sps_len = pst_codec_data->sps_len;
		int pps_len = pst_codec_data->pps_len;
		unsigned profileLevelId = (sps[1]<<16) | (sps[2]<<8) | sps[3];

		written_len = snprintf(p, remaining_len, "a=fmtp:%d packetization-mode=1;profile-level-id=%06X;sprop-parameter-sets=", pt, profileLevelId);
		if (written_len < 0 || written_len >= remaining_len) return -1;
		p += written_len;
		remaining_len -= written_len;

		base64_encode(p, remaining_len, sps, sps_len);
		written_len = strlen(p);
		if (written_len >= remaining_len) return -1;
		p += written_len;
		remaining_len -= written_len;

		written_len = snprintf(p, remaining_len, ",");
		if (written_len < 0 || written_len >= remaining_len) return -1;
		p += written_len;
		remaining_len -= written_len;

		base64_encode(p, remaining_len, pps, pps_len);
		written_len = strlen(p);
		if (written_len >= remaining_len) return -1;
		p += written_len;
		remaining_len -= written_len;

		written_len = snprintf(p, remaining_len, "\r\n");
		if (written_len < 0 || written_len >= remaining_len) return -1;
		p += written_len;
	} else {
		written_len = snprintf(p, remaining_len, "a=fmtp:%d packetization-mode=1\r\n", pt);
		if (written_len < 0 || written_len >= remaining_len) return -1;
		p += written_len;
	}

	return (p - sdpbuf);
}

int rtsp_build_sdp_media_attr_h265 (int pt, int sample_rate, const struct codec_data_h265 *pst_codec_data, char *sdpbuf, int maxlen)
{
	char *p = sdpbuf;
	int remaining_len = maxlen;
	int written_len;

	written_len = snprintf(p, remaining_len, "m=video 0 RTP/AVP %d\r\n", pt);
	if (written_len < 0 || written_len >= remaining_len) return -1;
	p += written_len;
	remaining_len -= written_len;

	written_len = snprintf(p, remaining_len, "a=rtpmap:%d H265/%d\r\n", pt, sample_rate);
	if (written_len < 0 || written_len >= remaining_len) return -1;
	p += written_len;
	remaining_len -= written_len;

	if (pst_codec_data->vps_len > 0 && pst_codec_data->sps_len > 0 && pst_codec_data->pps_len > 0) {
		const uint8_t *vps = pst_codec_data->vps;
		const uint8_t *sps = pst_codec_data->sps;
		const uint8_t *pps = pst_codec_data->pps;
		int vps_len = pst_codec_data->vps_len;
		int sps_len = pst_codec_data->sps_len;
		int pps_len = pst_codec_data->pps_len;

		written_len = snprintf(p, remaining_len, "a=fmtp:%d", pt);
		if (written_len < 0 || written_len >= remaining_len) return -1;
		p += written_len;
		remaining_len -= written_len;

		written_len = snprintf(p, remaining_len, " sprop-vps=");
		if (written_len < 0 || written_len >= remaining_len) return -1;
		p += written_len;
		remaining_len -= written_len;

		base64_encode(p, remaining_len, vps, vps_len);
		written_len = strlen(p);
		if (written_len >= remaining_len) return -1;
		p += written_len;
		remaining_len -= written_len;

		written_len = snprintf(p, remaining_len, ";sprop-sps=");
		if (written_len < 0 || written_len >= remaining_len) return -1;
		p += written_len;
		remaining_len -= written_len;

		base64_encode(p, remaining_len, sps, sps_len);
		written_len = strlen(p);
		if (written_len >= remaining_len) return -1;
		p += written_len;
		remaining_len -= written_len;

		written_len = snprintf(p, remaining_len, ";sprop-pps=");
		if (written_len < 0 || written_len >= remaining_len) return -1;
		p += written_len;
		remaining_len -= written_len;

		base64_encode(p, remaining_len, pps, pps_len);
		written_len = strlen(p);
		if (written_len >= remaining_len) return -1;
		p += written_len;
		remaining_len -= written_len;

		written_len = snprintf(p, remaining_len, "\r\n");
		if (written_len < 0 || written_len >= remaining_len) return -1;
		p += written_len;
	}

	return (p - sdpbuf);
}

int rtsp_build_sdp_media_attr_g711a (int pt, int sample_rate, char *sdpbuf, int maxlen)
{
	char *p = sdpbuf;
	int remaining_len = maxlen;
	int written_len;

	written_len = snprintf(p, remaining_len, "m=audio 0 RTP/AVP %d\r\n", pt);
	if (written_len < 0 || written_len >= remaining_len) return -1;
	p += written_len;
	remaining_len -= written_len;

	written_len = snprintf(p, remaining_len, "a=rtpmap:%d PCMA/%d/1\r\n", pt, sample_rate);
	if (written_len < 0 || written_len >= remaining_len) return -1;
	p += written_len;

	return (p - sdpbuf);
}

int rtsp_build_sdp_media_attr_g711u (int pt, int sample_rate, char *sdpbuf, int maxlen)
{
	char *p = sdpbuf;
	int remaining_len = maxlen;
	int written_len;

	written_len = snprintf(p, remaining_len, "m=audio 0 RTP/AVP %d\r\n", pt);
	if (written_len < 0 || written_len >= remaining_len) return -1;
	p += written_len;
	remaining_len -= written_len;

	written_len = snprintf(p, remaining_len, "a=rtpmap:%d PCMU/%d/1\r\n", pt, sample_rate);
	if (written_len < 0 || written_len >= remaining_len) return -1;
	p += written_len;

	return (p - sdpbuf);
}

int rtsp_build_sdp_media_attr_g726 (int pt, int sample_rate, const struct codec_data_g726 *pst_codec_data, char *sdpbuf, int maxlen)
{
	char *p = sdpbuf;
	int remaining_len = maxlen;
	int written_len;

	written_len = snprintf(p, remaining_len, "m=audio 0 RTP/AVP %d\r\n", pt);
	if (written_len < 0 || written_len >= remaining_len) return -1;
	p += written_len;
	remaining_len -= written_len;

	written_len = snprintf(p, remaining_len, "a=rtpmap:%d G726-%d/%d/1\r\n", pt,
		pst_codec_data->bit_rate ? pst_codec_data->bit_rate / 1000 : 32,
		sample_rate);
	if (written_len < 0 || written_len >= remaining_len) return -1;
	p += written_len;

	return (p - sdpbuf);
}

int rtsp_build_sdp_media_attr_aac (int pt, int sample_rate, const struct codec_data_aac *pst_codec_data, char *sdpbuf, int maxlen)
{
	char *p = sdpbuf;
	int remaining_len = maxlen;
	int written_len;

	written_len = snprintf(p, remaining_len, "m=audio 0 RTP/AVP %d\r\n", pt);
	if (written_len < 0 || written_len >= remaining_len) return -1;
	p += written_len;
	remaining_len -= written_len;

	written_len = snprintf(p, remaining_len, "a=rtpmap:%d MPEG4-GENERIC/%d/%d\r\n", pt,
		pst_codec_data->sample_rate ? pst_codec_data->sample_rate : 44100,
		pst_codec_data->channels ? pst_codec_data->channels : 2);
	if (written_len < 0 || written_len >= remaining_len) return -1;
	p += written_len;
	remaining_len -= written_len;

	if (pst_codec_data->audio_specific_config_len == 2) {
		written_len = snprintf(p, remaining_len, "a=fmtp:%d profile-level-id=1;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3;config=%02X%02X\r\n",
			pt, pst_codec_data->audio_specific_config[0], pst_codec_data->audio_specific_config[1]);
		if (written_len < 0 || written_len >= remaining_len) return -1;
		p += written_len;
	} else {
		written_len = snprintf(p, remaining_len, "a=fmtp:%d profile-level-id=1;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3\r\n", pt);
		if (written_len < 0 || written_len >= remaining_len) return -1;
		p += written_len;
	}
	return (p - sdpbuf);
}
