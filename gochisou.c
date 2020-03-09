#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

char *slurpfile(size_t *outlen, FILE *fp) {
	char *buf = 0;
	size_t bufsize = 0;

	struct stat st;
	if (fstat(fileno(fp), &st) == 0) {
		buf = realloc(0, st.st_size+1);
		if (buf) {
			*outlen = fread(buf, 1, st.st_size+1, fp);
			if (*outlen <= st.st_size)
				return buf;
			bufsize = st.st_size+1;
		}
	}

	for (;;) {
		bufsize *= 2;
		if (bufsize < 4096)
			bufsize = 4096;

		char *newbuf = realloc(buf, bufsize);
		if (newbuf == 0)
			err(2, "realloc");
		buf = newbuf;

		*outlen += fread(buf+*outlen, 1, bufsize-*outlen, fp);

		if (*outlen < bufsize)
			return newbuf;
	}
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

char *huff_encode(size_t *outlen, char *ssrc, size_t srclen) {
	uint8_t *src = (uint8_t *)ssrc;
	if (srclen >= 0x1000000)
		errx(1, "too big to huf");

	uint32_t freqs[256] = {0};
	for (int32_t j = 0; j < srclen; j++)
		freqs[src[j]]++;

	struct qnode {
		uint32_t freq;
		uint8_t leaf;
		uint8_t data;
	} queue[257] = {{0}};
	int16_t qlen = 0;
	for (int16_t j = 255; j >= 0; j--) {
		if (freqs[j]) {
			queue[qlen].freq = freqs[j];
			queue[qlen].leaf = 1;
			queue[qlen].data = j;
			qlen++;
		}
	}
	if (qlen == 1) {
		queue[qlen].freq = 0;
		queue[qlen].leaf = 1;
		queue[qlen].data = ~queue[0].data;
		qlen++;
	}

	struct tnode {
		uint8_t flags;
		uint8_t x0;
		uint8_t x1;
	} stems[256] = {{0}};
	int16_t tlen = 0;
	size_t encbits = 0;
	for (int16_t j = qlen; j > 1; j--) {
		for (int16_t k = 1; k < qlen; k++) {
			int16_t n = k;
			while (n >= 1 && queue[n-1].freq > queue[k].freq)
				n--;
			if (n != k) {
				memmove(queue+256, queue+k, sizeof queue[0]);
				memmove(queue+n+1, queue+n, (k-n)*sizeof queue[0]);
				memmove(queue+n, queue+256, sizeof queue[0]);
			}
		}

		int32_t freq = queue[0].freq + queue[1].freq;
		encbits += freq;
		queue[qlen].freq = freq;
		queue[qlen].leaf = 0;
		queue[qlen].data = tlen;
		stems[tlen].flags = queue[0].leaf + 2*queue[1].leaf;
		stems[tlen].x0 = queue[1].data;
		stems[tlen].x1 = queue[0].data;
		tlen++;
		qlen--;
		memmove(queue, queue+2, qlen*sizeof queue[0]);
	}
	stems[tlen].flags = 2;
	stems[tlen].x0 = tlen;
	stems[tlen].x1 = tlen-1;
	tlen++;

	*outlen = 4 + 2*tlen + ((((encbits-1)|31)+1)>>3);
	uint8_t *outbuf = realloc(0, *outlen);
	if (outbuf == 0)
		err(2, "realloc");
	outbuf[0] = 0x28;
	outbuf[1] = srclen;
	outbuf[2] = srclen >> 8;
	outbuf[3] = srclen >> 16;

	uint8_t place[256] = {0};
	for (int16_t j = tlen-1; j >= 0; j--) {
		uint8_t m = 0;
		for (int16_t k = 0; k < tlen; k++) {
			if (place[k])
				continue;

			struct tnode *s = stems+k;
			if ((!(s->flags & 2) && place[s->x0] >= j+64) || (!(s->flags & 1) && place[s->x1] >= j+64)) {
				m = k;
				break;
			}

			if (m == 0 && s->flags == 0 && (place[s->x0] || place[s->x1])) {
				uint8_t Q[256], L=0, R=0;
				Q[R++] = k;
				while (L < R) {
					struct tnode *w = stems+Q[L++];
					if (!(w->flags & 2) && !place[w->x0])
						Q[R++] = w->x0;
					if (!(w->flags & 1) && !place[w->x1])
						Q[R++] = w->x1;
				}
				if (R > 1)
					m = Q[R-1];
			}
		}
		while (place[m])
			m++;


		struct tnode *t = stems+m;
		if (t->flags & 2)
			outbuf[4+2*j+0] = t->x0;
		else if (place[t->x0] <= j+64)
			outbuf[4+2*j+0] = stems[t->x0].flags << 6 | (place[t->x0]-j-1);
		else errx(3, "oops %d %d %d", t->x0, place[t->x0], j);

		if (t->flags & 1)
			outbuf[4+2*j+1] = t->x1;
		else if (place[t->x1] <= j+64)
			outbuf[4+2*j+1] = stems[t->x1].flags << 6 | (place[t->x1]-j-1);
		else errx(4, "oops %d %d %d", t->x1, place[t->x1], j);

		place[m] = j;
	}

	uint32_t lookup[256] = {0};
	if (tlen > 1) {
		struct lstack {
			uint8_t n, w;
			uint32_t b;
		} lstack[256] = {{tlen-2, 0, 0}};
		int16_t slen = 1;
		while (slen > 0) {
			struct tnode *s = stems + lstack[slen-1].n;
			lstack[slen-1].w++;
			lstack[slen-1].b <<= 1;
			if (s->flags == 0) {
				lstack[slen-1].n = s->x0;
				lstack[slen].n = s->x1;
				lstack[slen].w = lstack[slen-1].w;
				lstack[slen].b = lstack[slen-1].b+1;
				slen++;
			}
			else if (s->flags == 1) {
				lookup[s->x1] = lstack[slen-1].w | lstack[slen-1].b << 5 | 1 << 5;
				lstack[slen-1].n = s->x0;
			}
			else if (s->flags == 2) {
				lookup[s->x0] = lstack[slen-1].w | lstack[slen-1].b << 5;
				lstack[slen-1].n = s->x1;
				lstack[slen-1].b++;
			}
			else if (s->flags == 3) {
				lookup[s->x0] = lstack[slen-1].w | lstack[slen-1].b << 5;
				lookup[s->x1] = lstack[slen-1].w | lstack[slen-1].b << 5 | 1 << 5;
				slen--;
			}
		}
	}

	uint32_t word = 0;
	int8_t bits = 32;
	size_t dp = 4 + 2*tlen;
	for (size_t sp = 0; sp < srclen; sp++) {
		uint8_t ch = src[sp];
		bits -= lookup[ch] & 31;
		if (bits < 0) {
			word |= lookup[ch] >> (5-bits);
			outbuf[dp++] = word;
			outbuf[dp++] = word >> 8;
			outbuf[dp++] = word >> 16;
			outbuf[dp++] = word >> 24;
			bits += 32;
			word = 0;
		}
		word |= (lookup[ch] >> 5) << bits;
	}
	outbuf[dp++] = word;
	outbuf[dp++] = word >> 8;
	outbuf[dp++] = word >> 16;
	outbuf[dp++] = word >> 24;

	return (char *)outbuf;
}

char *huff_decode(size_t *outlen, char *ssrc, size_t srclen) {
	uint8_t *src = (uint8_t *)ssrc;
	if (srclen <= 6 || srclen <= 6 + 2*src[4])
		errx(1, "huf buf insuf");
	if (src[0] != 0x28)
		errx(1, "not huffman mode 28");

	*outlen = src[1] | src[2] << 8 | src[3] << 16;
	char *outbuf = realloc(0, *outlen);
	if (outbuf == 0)
		err(2, "realloc");

	uint8_t *tree = src+4;
	uint8_t entry = tree[1];
	uint8_t pos = 0;

	size_t dp = 0;
	for (size_t sp = 6 + 2*src[4]; sp < srclen; sp += 4) {
		for (size_t sq = sp+3; sq >= sp; sq--) {
			for (uint8_t k = 128; k > 0; k >>= 1) {
				pos += (entry & 0x3f) + 1;
				if (pos > tree[0])
					errx(1, "pos out of tree");

				int isleaf;
				if (src[sq] & k) {
					isleaf = entry & 0x40;
					entry = tree[2*pos+1];
				}
				else {
					isleaf = entry & 0x80;
					entry = tree[2*pos];
				}

				if (isleaf) {
					outbuf[dp++] = entry;
					if (dp >= *outlen) {
						if (srclen-sp != 4)
							warnx("%td trailing bytes", srclen-sp);
						return outbuf;
					}
					entry = tree[1];
					pos = 0;
				}
			}
		}
	}

	warnx("huf buf not enough, missing %zu bytes", *outlen-dp);
	*outlen = dp;
	return outbuf;
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
		else if (strcmp(argv[j], "-") == 0) {
			outname = strdup("/dev/stdout");
			if (outname == 0)
				err(2, "strdup");
			argv[j] = "/dev/stdin";
		}

		FILE *src = fopen(argv[j], "rb");
		if (src == 0)
			err(2, "fopen %s", argv[j]);
		size_t namelen = strlen(argv[j]);

		size_t buflen;
		char *buf = slurpfile(&buflen, src);

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
