#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

char *slurpfile(size_t *outlen, FILE *fp, size_t limit) {
	char *buf = 0;
	size_t bufsize = 0;

	struct stat st;
	if (fstat(fileno(fp), &st) == 0 && st.st_size <= limit) {
		buf = realloc(0, st.st_size+1);
		if (buf) {
			*outlen = fread(buf, 1, st.st_size+1, fp);
			if (*outlen <= st.st_size)
				return buf;
			bufsize = st.st_size+1;
		}
	}

	/* let's be honest here, we all have mmus */
	char *newbuf = realloc(buf, limit);
	if (newbuf == 0)
		err(2, "realloc");
	bufsize += fread(newbuf+bufsize, 1, limit-bufsize, fp);
	*outlen = bufsize;
	return newbuf;
}

/* Reflected crc32 poly edb88320 */
uint32_t crc32(uint32_t reg, char *s, size_t len) {
	while (len-- > 0) {
		uint32_t x = (reg ^ *s++) & 255;
		for (int j = 0; j < 8; j++)
			x = (x>>1) ^ (x&1)*0xedb88320;
		reg = x ^ (reg>>8);
	}
	return reg;
}

static const char stupid_huff_tree[] =
"\xff\x00\x00\x01\x01\x02\x02\x03\x03\x04\x04\x05\x05\x06\x06\x07"
"\x07\x08\x08\x09\x09\x0a\x0a\x0b\x2b\x2c\x2c\x2d\x2d\x2e\x2e\x2f"
"\x07\x08\x08\x09\x09\x0a\x0a\x0b\x1b\x1c\x1c\x1d\x1d\x1e\x1e\x1f"
"\x07\x08\x08\x09\x09\x0a\x0a\x0b\x0b\x0c\x0c\x0d\x0d\x0e\x0e\x0f"
"\xdf\xe0\xe0\xe1\xe1\xe2\xe2\xe3\xe3\xe4\xe4\xe5\xe5\xe6\xe6\xe7"
"\xe7\xe8\xe8\xe9\xe9\xea\xea\xeb\xeb\xec\xec\xed\xed\xee\xee\xef"
"\x2f\x30\x30\x31\x31\x32\x32\x33\x33\x34\x34\x35\x35\x36\x36\x37"
"\x37\x38\x38\x39\x39\x3a\x3a\x3b\x3b\x3c\x3c\x3d\x3d\x3e\x3e\x3f"
"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
"\xdf\xe0\xe0\xe1\xe1\xe2\xe2\xe3\xe3\xe4\xe4\xe5\xe5\xe6\xe6\xe7"
"\xe7\xe8\xe8\xe9\xe9\xea\xea\xeb\xeb\xec\xec\xed\xed\xee\xee\xef"
"\x2f\x30\x30\x31\x31\x32\x32\x33\x33\x34\x34\x35\x35\x36\x36\x37"
"\x37\x38\x38\x39\x39\x3a\x3a\x3b\x3b\x3c\x3c\x3d\x3d\x3e\x3e\x3f"
"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
"\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
"\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\xdf\xe0\xe0\xe1\xe1\xe2\xe2\xe3\xe3\xe4\xe4\xe5\xe5\xe6\xe6\xe7"
"\xe7\xe8\xe8\xe9\xe9\xea\xea\xeb\xeb\xec\xec\xed\xed\xee\xee\xef"
"\xef\xf0\xf0\xf1\xf1\xf2\xf2\xf3\xf3\xf4\xf4\xf5\xf5\xf6\xf6\xf7"
"\xf7\xf8\xf8\xf9\xf9\xfa\xfa\xfb\xfb\xfc\xfc\xfd\xfd\xfe\xfe\xff"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
"\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";

/* Included only for the sake of completeness; it doesn't compress! This isn't
 * very useful since the games can handle uncompressed save files just fine. */
char *huff_encode(size_t *outlen, char *src, size_t srclen) {
	if (srclen >= 0x1000000)
		errx(1, "too big to huf");
	*outlen = (srclen-1|3)+517;
	char *buf = realloc(0, *outlen);
	if (buf == 0)
		err(2, "realloc");

	buf[0] = 0x28;
	buf[1] = srclen; 
	buf[2] = srclen >> 8; 
	buf[3] = srclen >> 16;
	memmove(buf+4, stupid_huff_tree, 512);

	for (size_t j = 0; j <= (srclen-1|3); j++) {
		if (516+(j|3)-(j&3) >= *outlen)
			errx(3, "impossible");
		buf[516+(j|3)-(j&3)] = j < srclen ? src[j] : 0;
	}

	return buf;
}

char *huff_decode(size_t *outlen, char *ssrc, size_t srclen) {
	uint8_t *src = (uint8_t *)ssrc;
	if (srclen <= 6 || srclen <= 6 + 2*src[4])
		errx(1, "huf buf insuf");
	uint8_t *srcend = src + srclen;

	if (src[0] != 0x28)
		errx(1, "not huffman mode 28");

	*outlen = src[1] | src[2] << 8 | src[3] << 16;
	char *buf = realloc(0, *outlen);
	if (buf == 0)
		err(2, "realloc");

	uint8_t *tree = src+4;
	uint8_t entry = tree[1];
	uint8_t pos = 0;

	char *bufend = buf + *outlen;
	char *dp = buf;
	for (uint8_t *sp = src + 6 + 2*src[4]; sp < srcend; sp += 4) {
		for (uint8_t *dq = sp+3; dq >= sp; dq--) {
			for (int k = 128; k > 0; k >>= 1) {
				pos += (entry & 0x3f) + 1;
				if (pos > tree[0])
					errx(1, "pos out of tree");

				int isleaf;
				if (*dq & k) {
					isleaf = entry & 0x40;
					entry = tree[2*pos+1];
				}
				else {
					isleaf = entry & 0x80;
					entry = tree[2*pos];
				}

				if (isleaf) {
					*dp++ = entry;
					if (dp >= bufend) {
						if (srcend-sp != 4)
							warnx("%td trailing bytes", srcend-sp);
						return buf;
					}
					entry = tree[1];
					pos = 0;
				}
			}
		}
	}

	warnx("huf buf not enough");
	*outlen = dp-buf;
	return buf;
}

static uint32_t little32(char *p) {
	uint8_t *q = (uint8_t *)p;
	return q[0] | q[1] << 8 | q[2] << 16 | q[3] << 24;
}

int main(int argc, char **argv) {
	for (int j = 1; j < argc; j++) {
		char *outname = 0;
		if (strcmp(argv[j], "-o") == 0) {
			outname = strdup(argv[j+1]);
			if (outname == 0)
				err(2, "strdup");
			j += 2;
			if (j >= argc)
				break;
		}

		FILE *src = fopen(argv[j], "rb");
		if (src == 0)
			err(2, "fopen %s", argv[j]);
		size_t namelen = strlen(argv[j]);

		size_t buflen;
		char *buf = slurpfile(&buflen, src, 0x1000204);

		char *sect = 0;
		int enc = 0;
		for (char *p = buf; p+4 <= buf+buflen && p-buf < 1024; p += 16) {
			if (memcmp(p, "PMOC", 4) == 0) {
				sect = p;
				break;
			}
			else if (memcmp(p, "EDNI", 4) == 0) {
				sect = p;
				enc = 1;
				break;
			}
		}
		if (sect == 0)
			errx(1, "%s is probably not a 3dsfe save file", argv[j]);

		int offset = sect-buf;
		if (enc) {
			uint32_t crc = ~crc32(~0, buf, buflen);
			uint32_t declen = buflen-offset;
			char pmoc_header[16] = {
				'P', 'M', 'O', 'C', 2, 0, 0, 0,
				declen, declen>>8, declen>>16, declen>>24,
				crc, crc>>8, crc>>16, crc>>24
			};
			size_t enclen;
			char *enc = huff_encode(&enclen, sect, declen);

			if (outname == 0) {
				outname = realloc(0, namelen+5);
				if (strcmp(argv[j]+namelen-4, "_dec") == 0)
					snprintf(outname, namelen-3, "%s", argv[j]);
				else
					snprintf(outname, namelen+5, "%s_enc", argv[j]);
			}

			FILE *dst = fopen(outname, "wb");
			if (dst == 0)
				err(2, "fopen %s", outname);
			warnx("encoding %s to %s", argv[j], outname);
			if (dst == 0)
				err(2, "fopen %s", outname);

			fwrite(buf, 1, offset, dst);
			fwrite(pmoc_header, 1, 16, dst);
			fwrite(enc, 1, enclen, dst);

			fclose(dst);
			free(outname);
			free(enc);
		}
		else {
			uint32_t expectlen = little32(sect+8);
			uint32_t expectcrc = little32(sect+12);
			int hufset = offset+16;
			size_t declen;
			char *dec = huff_decode(&declen, buf+hufset, buflen-hufset);

			if (declen != expectlen)
				errx(1, "%s decompressed size mismatch", argv[j]);
			uint32_t crc = ~crc32(crc32(~0, buf, offset), dec, declen);
			if (crc != expectcrc)
				warnx("%s decompressed crc mismatch (expected %08x, was %08x)", argv[j], expectcrc, crc);

			if (outname == 0) {
				outname = realloc(0, namelen+5);
				if (strcmp(argv[j]+namelen-4, "_enc") == 0)
					snprintf(outname, namelen-3, "%s", argv[j]);
				else
					snprintf(outname, namelen+5, "%s_dec", argv[j]);
			}

			FILE *dst = fopen(outname, "wb");
			if (dst == 0)
				err(2, "fopen %s", outname);
			warnx("decoding %s to %s", argv[j], outname);
			if (dst == 0)
				err(2, "fopen %s", outname);

			fwrite(buf, 1, offset, dst);
			fwrite(dec, 1, declen, dst);

			fclose(dst);
			free(outname);
			free(dec);
		}
		free(buf);
		fclose(src);
	}
}
