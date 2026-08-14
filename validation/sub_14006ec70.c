// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F3600();
__int64 sub_1400FA1B0();
__int64 sub_14008A6C0();
__int64 sub_14007BF40();
__int64 sub_1400FA650();
__int64 sub_1400FAB20();
__int64 sub_1400F2D20();
__int64 sub_1400207F0();
__int64 sub_14008AB40();
__int64 sub_14008A830();
__int64 sub_14008B890();
__int64 sub_1400F37A0();
__int64 sub_1400F37D0();
__int64 sub_1400FA0D0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140117728;
extern __int64 off_14011D5E0;
extern __int64 off_14011D5D0;
extern __int64 off_140108850;
extern __int64 off_14012D270;
extern __int64 off_140018400;
extern __int64 off_1401178A8;
extern __int64 off_140117930;
extern __int64 off_140117948;
extern __int64 off_140117978;

__int64 __fastcall sub_14006EC70(size_t *a1, size_t *a2) {
    __int64 rsp;
    int arg_10;
    int arg_18;
    int arg_2;
    int arg_20;
    int arg_208;
    int arg_28;
    int arg_4;
    int arg_68;
    int arg_6c;
    int arg_8;
    int arg_9;
    int arg_b;
    int arg_dc;
    int arg_e0;
    __int64 v_10;
    __int64 v_100;
    int v_110;
    int v_118;
    int v_120;
    int i;
    int v_130;
    int v_138;
    int v_140;
    int v_148;
    __int64 v_158;
    int v_160;
    int v_168;
    int v_170;
    int v_178;
    int v_180;
    int v_188;
    int v_190;
    int v_198;
    __int64 v_1a0;
    int v_1a8;
    int v_1b0;
    __int64 v_1d0;
    __int64 v_1d8;
    int v_1e0;
    int v_1e8;
    int v_1f0;
    int v_20;
    __int64 v_208;
    int v_210;
    int v_218;
    int v_220;
    __int64 v_228;
    int v_230;
    __int64 v_238;
    __int64 v_240;
    int v_258;
    int v_260;
    int v_270;
    __int64 v_28;
    __int64 v_3;
    __int64 v_30;
    __int64 v_38;
    int v_47;
    __int64 v_48;
    __int64 v_54;
    __int64 v_56;
    __int64 v_58;
    int v_5a;
    __int64 v_5c;
    int v_5e;
    int v_60;
    int v_68;
    int v_70;
    int v_78;
    __int64 v_80;
    __int64 v_88;
    __int64 v_90;
    __int64 v_98;
    __int64 v_a0;
    int v_a8;
    __int64 v_b0;
    __int64 v_b8;
    __int64 v_c;
    int v_c8;
    __int64 v_d0;
    __int64 v_d8;
    int v_e0;
    __int64 v_e8;
    int v_f0;
    int v_f8;
    int *v_0;
    int *v_4;
    int *v_8;
    __int64 *src;
    __int64 *result;
    __int64 *dst;
    __int64 v5;
    __int64 v6;
    __int64 *dst2;
    __int64 *dst3;
    struct Struct_1_t *ptr;
    __int64 v11;
    __int64 i2;
    __int64 *src2;
    __m128i xmm0;
    __int64 v10;
    __int64 *src3;
    __m128i xmm1;
    __m128i xmm6;
    __m128i xmm7;
    __m128i xmm2;

    _mm_store_si128((__m128i *)&v_270, xmm7);
    _mm_store_si128((__m128i *)&v_260, xmm6);
    v_80 = 0;
    v_88 = 4;
    v_90 = 0;
    v_168 = (int)a2;
    v_160 = (int)a1;
    if (!((arg_e0 < 4))) {
        src = (__int64 *)a2;
        result = (__int64 *)arg_68;
        dst = (__int64 *)arg_6c;
        a1 = (size_t *)dst;
        a1 = (size_t *)((__int64)(__int64)a1 | (__int64)result);
        if (!((a1 == 0))) {
            a1 = (size_t *)arg_20;
            v5 = arg_28;
            a1 -= 28;
            a2 = v5 + v5*8;
            a2 += (__int64)(__int64)a2*2;
            a2 += v5;
            while (a2 != 0) {
                v6 = a1[4];
                dst2 = a1[5];
                v5 = a1[5];
                if (v5 > v6) v6 = v5;
                v6 += (__int64)dst2;
                if (!((v6 < 0))) {
                    a1 += 28;
                    a2 -= 28;
                    dst3 = result;
                    dst3 = (__int64 *)((__int64)dst3 - (__int64)dst2);
                    if (dst3 < v5) {
                        result = a1[2];
                        a1 = result + v6;
                        v5 = arg_10;
                        if (a1 < v5) {
                            a2 = (__int64)a1 + (__int64)dst;
                            if (a2 <= v5) {
                                if (a2 > v5) {
                                    v6 = &off_140117728;
                                    sub_1400F3600(a1, a2, v6, v6);
                                } else {
                                    if (dst >= 12) {
                                        a1 = (size_t *)dst;
                                        a2 = 0xAAAAAAAB;
                                        a2 = (size_t *)((__int64)(__int64)(__int64)a2 * (__int64)a1);
                                        result += arg_8;
                                        a2 = (size_t *)((__int64)(__int64)a2 >> 35);
                                        ptr = v6 + result;
                                        ptr += 4;
                                        a2 = (size_t *)((__int64)(__int64)a2 << 2);
                                        v11 = a2 + (__int64)(__int64)a2*2;
                                        result = 4;
                                        i2 = 0;
                                        src = rsp + 128;
                                        a2 = 0;
                                        do {
                                            a1 = i2 + 4;
                                            src2 = 0;
                                            a1 = i2 + 8;
                                            if (a1 > dst) {
                                                i2 += 12;
                                                v5 = v_80;
                                                a1 = (size_t *)v_88;
                                                result = a2 + (__int64)(__int64)a2*2;
                                                v_48 = (__int64)a1;
                                                ptr = a1 + (__int64)(__int64)result*4;
                                                xmm0 = _mm_loadu_si128((__m128i *)&off_14011D5E0);
                                                _mm_store_si128((__m128i *)&v_90, xmm0);
                                                xmm0 = _mm_loadu_si128((__m128i *)&off_14011D5D0);
                                                _mm_store_si128((__m128i *)&v_80, xmm0);
                                                v_c8 = v5;
                                                if (a2 != 0) {
                                                    v5 = rsp + 160;
                                                    src = rsp + 128;
                                                    v10 = (__int64)a2;
                                                    sub_1400FA1B0(src, a2, v5, v6);
                                                    src3 = (__int64 *)v_48;
                                                    i2 = (__int64)a2;
                                                    do {
                                                        a2 = *src3;
                                                        sub_14008A6C0(src, a2);
                                                        src3 += 12;
                                                        src2 = 0;
                                                        --v10;
                                                    } while ((v10 != 0));
                                                    v5 = i2;
                                                } else {
                                                    src2 = 1;
                                                    v5 = 0;
                                                }
                                                xmm0 = _mm_load_si128((__m128i *)&v_80);
                                                xmm1 = _mm_load_si128((__m128i *)&v_90);
                                                _mm_store_si128((__m128i *)&v_1f0, xmm1);
                                                _mm_store_si128((__m128i *)&v_1e0, xmm0);
                                                v5 += 16;
                                                a1 = rsp + 128;
                                                sub_14007BF40(a1, 16, v5, dst3);
                                                xmm0 = _mm_loadu_si128((__m128i *)&v_80);
                                                xmm1 = _mm_loadu_si128((__m128i *)&v_90);
                                                _mm_store_si128((__m128i *)&v_70, xmm1);
                                                _mm_store_si128((__m128i *)&v_60, xmm0);
                                                if (src2 == 0) {
                                                    xmm6 = _mm_cmpeq_epi32(xmm6, xmm6);
                                                    xmm7 = _mm_load_si128((__m128i *)&off_140108850);
                                                    src = (__int64 *)v_48;
                                                    src2 = (__int64 *)arg_8;
                                                    while (src2 != 3) {
                                                        v10 = *src;
                                                        result = (__int64 *)arg_b;
                                                        v_56 = (__int64)result;
                                                        result = (__int64 *)arg_9;
                                                        v_54 = (__int64)result;
                                                        if (v_70 == 0) {
                                                            a1 = rsp + 96;
                                                            a2 = rsp + 128;
                                                            sub_1400FA650(a1, a2, v5, v6);
                                                        }
                                                        src += 12;
                                                        v6 = v10;
                                                        result = 0xF1357AEA2E62A9C5;
                                                        v6 *= (__int64)result;
                                                        v6 = __ROL8__(v6, 26);
                                                        dst = (__int64 *)v_60;
                                                        a2 = (size_t *)v_68;
                                                        a1 = (size_t *)v6;
                                                        a1 = (size_t *)((__int64)(__int64)a1 >> 57);
                                                        xmm0 = _mm_cvtsi32_si128(a1);
                                                        xmm0 = _mm_unpacklo_epi8(xmm0, xmm0);
                                                        xmm0 = _mm_shufflelo_epi16(xmm0, 0);
                                                        xmm0 = _mm_shuffle_epi32(xmm0, 68);
                                                        dst2 = 0;
                                                        dst3 = 0;
                                                        do {
                                                            v6 &= (__int64)a2;
                                                            xmm1 = _mm_loadu_si128((__m128i *)(dst + v6));
                                                            xmm2 = xmm1;
                                                            xmm2 = _mm_cmpeq_epi8(xmm2, xmm0);
                                                            src3 = _mm_movemask_epi8(xmm2);
                                                            if (dst2 == 1) {
                                                                xmm1 = _mm_cmpeq_epi8(xmm1, xmm6);
                                                                result = _mm_movemask_epi8(xmm1);
                                                                if (result != 0) {
                                                                    v5 = *(dst + i2);
                                                                    if (v5 >= 0) {
                                                                        xmm0 = _mm_load_si128((__m128i *)dst);
                                                                        result = _mm_movemask_epi8(xmm0);
                                                                        i2 = __builtin_ctz(result);
                                                                        v5 = *(dst + i2);
                                                                    }
                                                                    v5 &= 1;
                                                                    result = i2 - 16;
                                                                    result = (__int64 *)((__int64)(__int64)result & (__int64)a2);
                                                                    *(dst + i2) = a1;
                                                                    *(__int64 *)((__int64)dst + (__int64)result + 16) = a1;
                                                                    xmm0 = _mm_load_si128((__m128i *)&v_70);
                                                                    result = (__int64 *)v5;
                                                                    xmm1 = _mm_cvtsi32_si128(result);
                                                                    /* shufps $228, %xmm7, %xmm1 */;
                                                                    xmm0 = _mm_sub_epi64(xmm0, xmm1);
                                                                    _mm_store_si128((__m128i *)&v_70, xmm0);
                                                                    v5 = i2;
                                                                    v5 = -v5;
                                                                    i2 <<= 4;
                                                                    result = dst;
                                                                    result -= i2;
                                                                    i2 = -i2;
                                                                    *(dst + i2 - 16) = v10;
                                                                    v_c = v10;
                                                                    v_4 = (int *)src2;
                                                                    v5 <<= 4;
                                                                    result = (__int64 *)v_56;
                                                                    *(dst + v5 - 1) = result;
                                                                    result = (__int64 *)v_54;
                                                                    *(dst + v5 - 3) = result;
                                                                    if (v_c8 != 0) {
                                                                        off_140108030();
                                                                        v5 = v_48;
                                                                        off_140108038(result, 0, v5);
                                                                    }
                                                                    result = (__int64 *)v_168;
                                                                    dst = (__int64 *)arg_dc;
                                                                    xmm0 = _mm_loadu_si128((__m128i *)&off_14011D5E0);
                                                                    _mm_store_si128((__m128i *)&v_120, xmm0);
                                                                    xmm1 = _mm_loadu_si128((__m128i *)&off_14011D5D0);
                                                                    _mm_store_si128((__m128i *)&v_110, xmm1);
                                                                    _mm_store_si128((__m128i *)&v_140, xmm0);
                                                                    _mm_store_si128((__m128i *)&v_130, xmm1);
                                                                    if (dst != 0) {
                                                                        v_f0 = 0;
                                                                        v_f8 = 4;
                                                                        v_100 = 0;
                                                                        a1 = rsp + 240;
                                                                        sub_1400FAB20(a1);
                                                                        result = (__int64 *)v_f8;
                                                                        *result = dst;
                                                                        arg_4 = 1;
                                                                        v_100 = 1;
                                                                        result = off_14012D270;
                                                                        a1 = __readgsqword(88);
                                                                        result = v_0[(__int64)result];
                                                                        result += 24;
                                                                        v_1a0 = (__int64)result;
                                                                        dst = 1;
                                                                        xmm6 = _mm_cmpeq_epi32(xmm6, xmm6);
                                                                        xmm7 = _mm_load_si128((__m128i *)&off_140108850);
                                                                        do {
                                                                            ptr = (struct Struct_1_t *)v_f8;
                                                                            v6 = v_120;
                                                                            src = ptr + 8;
                                                                            v11 = dst - 1;
                                                                            i2 = 0;
                                                                            do {
                                                                                src3 = ((__int64 *)ptr)[i2];
                                                                                a1 = rsp + 272;
                                                                                v5 = rsp + 304;
                                                                                sub_1400FA1B0(a1, 1, v5, v6);
                                                                                v6 = (__int64)src3;
                                                                                result = 0xF1357AEA2E62A9C5;
                                                                                v6 *= (__int64)result;
                                                                                v6 = __ROL8__(v6, 26);
                                                                                dst3 = (__int64 *)v_110;
                                                                                a2 = (size_t *)v_118;
                                                                                a1 = (size_t *)v6;
                                                                                a1 = (size_t *)((__int64)(__int64)a1 >> 57);
                                                                                xmm0 = _mm_cvtsi32_si128(a1);
                                                                                xmm0 = _mm_unpacklo_epi8(xmm0, xmm0);
                                                                                xmm0 = _mm_shufflelo_epi16(xmm0, 0);
                                                                                xmm0 = _mm_shuffle_epi32(xmm0, 68);
                                                                                result = 0;
                                                                                dst2 = 0;
                                                                                do {
                                                                                    v6 &= (__int64)a2;
                                                                                    xmm1 = _mm_loadu_si128((__m128i *)(dst3 + v6));
                                                                                    xmm2 = xmm1;
                                                                                    xmm2 = _mm_cmpeq_epi8(xmm2, xmm0);
                                                                                    v10 = _mm_movemask_epi8(xmm2);
                                                                                    v5 = v_48;
                                                                                    if (result == 1) {
                                                                                        xmm1 = _mm_cmpeq_epi8(xmm1, xmm6);
                                                                                        result = _mm_movemask_epi8(xmm1);
                                                                                        if (result != 0) {
                                                                                            v6 = *(dst3 + v5);
                                                                                            if (v6 >= 0) {
                                                                                                xmm0 = _mm_load_si128((__m128i *)dst3);
                                                                                                result = _mm_movemask_epi8(xmm0);
                                                                                                v5 = __builtin_ctz(result);
                                                                                                v6 = *(dst3 + v5);
                                                                                            }
                                                                                            v6 &= 1;
                                                                                            result = (__int64 *)v6;
                                                                                            v6 = v_120;
                                                                                            v6 -= (__int64)result;
                                                                                            v_120 = v6;
                                                                                            result = v5 - 16;
                                                                                            result = (__int64 *)((__int64)(__int64)result & (__int64)a2);
                                                                                            *(dst3 + v5) = a1;
                                                                                            *(__int64 *)((__int64)dst3 + (__int64)result + 16) = a1;
                                                                                            ++i;
                                                                                            v5 <<= 2;
                                                                                            v5 = -v5;
                                                                                            *(dst3 + v5 - 4) = src3;
                                                                                            ++i2;
                                                                                            src += 8;
                                                                                            --v11;
                                                                                            v10 = 0;
                                                                                            src3 = dst;
                                                                                            src3 -= v10;
                                                                                            v_100 = (__int64)src3;
                                                                                            if ((src3 != 0)) {
                                                                                                v_188 = 0;
                                                                                                v_190 = 8;
                                                                                                v_198 = 0;
                                                                                                v_1d0 = (__int64)src3;
                                                                                                v_20 = 40;
                                                                                                a1 = rsp + 392;
                                                                                                sub_1400F2D20(a1, 0, src3, 8);
                                                                                                i2 = v_188;
                                                                                                src = (__int64 *)v_198;
                                                                                                result = (__int64 *)i2;
                                                                                                result = (__int64 *)((__int64)result - (__int64)src);
                                                                                                if (result >= src3) {
                                                                                                    v11 = v_190;
                                                                                                    result = src + (__int64)(__int64)src*4;
                                                                                                    result = v11 + (__int64)(__int64)result*8;
                                                                                                    v_d0 = (__int64)ptr;
                                                                                                    v_d8 = (__int64)src3;
                                                                                                    a1 = rsp + 480;
                                                                                                    v_e0 = (int)a1;
                                                                                                    a1 = (size_t *)v_168;
                                                                                                    v_e8 = (__int64)a1;
                                                                                                    v_98 = (__int64)src3;
                                                                                                    a1 = rsp + 224;
                                                                                                    v_80 = (__int64)a1;
                                                                                                    v_88 = (__int64)result;
                                                                                                    v_90 = (__int64)src3;
                                                                                                    result = (__int64 *)v_1a0;
                                                                                                    result = *result;
                                                                                                    if (result == 0) {
                                                                                                        sub_1400207F0(a1);
                                                                                                        v_1b0 = i2;
                                                                                                        result = *result;
                                                                                                        v6 = arg_208;
                                                                                                        result = rsp + 128;
                                                                                                        v_38 = (__int64)result;
                                                                                                        v_30 = (__int64)src3;
                                                                                                        v_28 = (__int64)ptr;
                                                                                                        v_20 = 1;
                                                                                                        a1 = rsp + 584;
                                                                                                        sub_14008AB40(a1, src3, 0, v6);
                                                                                                        result = (__int64 *)v_258;
                                                                                                        v_1d8 = (__int64)result;
                                                                                                        if (result == src3) {
                                                                                                            src3 = (__int64 *)((__int64)src3 + (__int64)src);
                                                                                                            v_170 = 0;
                                                                                                            v_178 = 4;
                                                                                                            v_180 = 0;
                                                                                                            result = src3 + (__int64)(__int64)src3*4;
                                                                                                            result = v11 + (__int64)(__int64)result*8;
                                                                                                            v_158 = (__int64)result;
                                                                                                            dst = (__int64 *)((__int64)dst + (__int64)src);
                                                                                                            dst = (__int64 *)((__int64)(__int64)dst << 3);
                                                                                                            src3 = dst + (__int64)(__int64)dst*4;
                                                                                                            v10 <<= 3;
                                                                                                            result =  + v10*4;
                                                                                                            result += v10;
                                                                                                            src3 = (__int64 *)((__int64)src3 - (__int64)result);
                                                                                                            src3 -= 40;
                                                                                                            src = v11 + 64;
                                                                                                            dst = 4;
                                                                                                            result = (__int64 *)v11;
                                                                                                            i2 = 0;
                                                                                                            v_1a8 = v11;
                                                                                                            a2 = result + 40;
                                                                                                            v11 = arg_10;
                                                                                                            a1 = (size_t *)v11;
                                                                                                            a1 = (size_t *)(-(__int64)a1);
                                                                                                            while (!((0 /* overflow check on (-a1) */))) {
                                                                                                                v_c8 = (int)a2;
                                                                                                                a2 = (size_t *)arg_8;
                                                                                                                a1 = (size_t *)arg_18;
                                                                                                                v_48 = (__int64)a1;
                                                                                                                v10 = arg_20;
                                                                                                                if (a2 == 3) {
                                                                                                                    if (v10 == 0) {
                                                                                                                        if (v11 == 0) {
                                                                                                                            src3 -= 40;
                                                                                                                            src += 40;
                                                                                                                            a1 = (size_t *)v_c8;
                                                                                                                            result = (__int64 *)a1;
                                                                                                                            if (v_1b0 == 0) {
                                                                                                                                if (v_f0 == 0) {
                                                                                                                                    dst = (__int64 *)v_180;
                                                                                                                                    v_100 = (__int64)dst;
                                                                                                                                    xmm0 = _mm_loadu_si128((__m128i *)&v_170);
                                                                                                                                    _mm_store_si128((__m128i *)&v_f0, xmm0);
                                                                                                                                    a1 = (size_t *)v_130;
                                                                                                                                    a2 = (size_t *)v_138;
                                                                                                                                    result = (__int64 *)v_148;
                                                                                                                                    xmm0 = _mm_load_si128((__m128i *)a1);
                                                                                                                                    if (a2 == 0) {
                                                                                                                                        dst3 = 0;
                                                                                                                                    } else {
                                                                                                                                        dst3 = (__int64 *)a2;
                                                                                                                                        dst3 = (__int64 *)((__int64)(__int64)dst3 << 4);
                                                                                                                                        v5 = (__int64)dst3 + (__int64)a2;
                                                                                                                                        v5 += 33;
                                                                                                                                        v6 = (__int64)a1;
                                                                                                                                        v6 -= (__int64)dst3;
                                                                                                                                        v6 -= 16;
                                                                                                                                        dst3 = 16;
                                                                                                                                    }
                                                                                                                                    dst2 = a1 + 16;
                                                                                                                                    dst = _mm_movemask_epi8(xmm0);
                                                                                                                                    dst = (__int64 *)(~(__int64)dst);
                                                                                                                                    a2 = (size_t *)((__int64)a2 + (__int64)a1);
                                                                                                                                    ++a2;
                                                                                                                                    v_80 = (__int64)dst3;
                                                                                                                                    v_88 = v5;
                                                                                                                                    v_90 = v6;
                                                                                                                                    v_98 = (__int64)a1;
                                                                                                                                    v_a0 = (__int64)dst2;
                                                                                                                                    v_a8 = (int)a2;
                                                                                                                                    v_b0 = (__int64)dst;
                                                                                                                                    v_b8 = (__int64)result;
                                                                                                                                    a1 = rsp + 208;
                                                                                                                                    a2 = rsp + 128;
                                                                                                                                    sub_14008A830(a1, a2, v5, v6);
                                                                                                                                    a2 = (size_t *)v_e0;
                                                                                                                                    if (a2 >= 2) {
                                                                                                                                        a1 = (size_t *)v_d8;
                                                                                                                                        if (a2 >= 21) JUMPOUT(0x1400700d3);
                                                                                                                                        result = a2 + (__int64)(__int64)a2*2;
                                                                                                                                        result = a1 + (__int64)(__int64)result*4;
                                                                                                                                        v6 = a1 + 12;
                                                                                                                                        a2 = 12;
                                                                                                                                        dst3 = (__int64 *)a1;
                                                                                                                                        do {
                                                                                                                                            v6 = *(dst3 + 12);
                                                                                                                                            v6 = v5 + 12;
                                                                                                                                            a2 += 12;
                                                                                                                                            dst3 = (__int64 *)v5;
                                                                                                                                        } while (v6 != result);
                                                                                                                                    }
                                                                                                                                    if (v_f0 != 0) {
                                                                                                                                        ptr = (struct Struct_1_t *)v_f8;
                                                                                                                                        off_140108030(a1, a2);
                                                                                                                                        off_140108038(result, 0, ptr);
                                                                                                                                    }
                                                                                                                                    a1 = (size_t *)v_118;
                                                                                                                                    if (a1 != 0) {
                                                                                                                                        result =  + (__int64)(__int64)a1*4 + 19;
                                                                                                                                        result = (__int64 *)((__int64)(__int64)result & -16);
                                                                                                                                        a1 = (size_t *)((__int64)a1 + (__int64)result);
                                                                                                                                        if (a1 != -17) {
                                                                                                                                            ptr = (struct Struct_1_t *)v_110;
                                                                                                                                            ptr = (struct Struct_1_t *)((__int64)ptr - (__int64)result);
                                                                                                                                            off_140108030(a1);
                                                                                                                                            off_140108038(result, 0, ptr);
                                                                                                                                        }
                                                                                                                                    }
                                                                                                                                    result = (__int64 *)v_d0;
                                                                                                                                    v_48 = (__int64)result;
                                                                                                                                    ptr = (struct Struct_1_t *)v_d8;
                                                                                                                                    result = (__int64 *)v_e0;
                                                                                                                                    if (result != 0) {
                                                                                                                                        result += (__int64)(__int64)result*2;
                                                                                                                                        i2 = ptr + (__int64)(__int64)result*4;
                                                                                                                                        xmm6 = _mm_cmpeq_epi32(xmm6, xmm6);
                                                                                                                                        xmm7 = _mm_load_si128((__m128i *)&off_140108850);
                                                                                                                                        result = (__int64 *)ptr;
                                                                                                                                        v10 = arg_8;
                                                                                                                                        while (v10 != 3) {
                                                                                                                                            src3 = result + 12;
                                                                                                                                            src2 = *result;
                                                                                                                                            a1 = (size_t *)arg_b;
                                                                                                                                            v_5a = (int)a1;
                                                                                                                                            result = (__int64 *)arg_9;
                                                                                                                                            src = src2;
                                                                                                                                            a1 = 0xF1357AEA2E62A9C5;
                                                                                                                                            src = (__int64 *)((__int64)(__int64)(__int64)src * (__int64)a1);
                                                                                                                                            src = __ROL8__(src, 26);
                                                                                                                                            v_58 = (__int64)result;
                                                                                                                                            v11 = (__int64)src;
                                                                                                                                            v11 >>= 57;
                                                                                                                                            result = (__int64 *)v_60;
                                                                                                                                            a1 = (size_t *)v_68;
                                                                                                                                            xmm0 = _mm_cvtsi32_si128(v11);
                                                                                                                                            xmm0 = _mm_unpacklo_epi8(xmm0, xmm0);
                                                                                                                                            xmm0 = _mm_shufflelo_epi16(xmm0, 0);
                                                                                                                                            xmm0 = _mm_shuffle_epi32(xmm0, 68);
                                                                                                                                            dst = result - 16;
                                                                                                                                            v5 = 0;
                                                                                                                                            do {
                                                                                                                                                v6 &= (__int64)a1;
                                                                                                                                                xmm1 = _mm_loadu_si128((__m128i *)(result + v6));
                                                                                                                                                xmm2 = xmm1;
                                                                                                                                                xmm2 = _mm_cmpeq_epi8(xmm2, xmm0);
                                                                                                                                                dst3 = _mm_movemask_epi8(xmm2);
                                                                                                                                                xmm1 = _mm_cmpeq_epi8(xmm1, xmm6);
                                                                                                                                                a2 = _mm_movemask_epi8(xmm1);
                                                                                                                                                if (a2 != 0) {
                                                                                                                                                    if (v_70 == 0) {
                                                                                                                                                        a1 = rsp + 96;
                                                                                                                                                        a2 = rsp + 128;
                                                                                                                                                        sub_1400FA650(a1, a2, v5, src);
                                                                                                                                                        result = (__int64 *)v_60;
                                                                                                                                                        a1 = (size_t *)v_68;
                                                                                                                                                    }
                                                                                                                                                    src = (__int64 *)((__int64)(__int64)src & (__int64)a1);
                                                                                                                                                    xmm0 = _mm_loadu_si128((__m128i *)((__int64)result + (__int64)src));
                                                                                                                                                    a2 = _mm_movemask_epi8(xmm0);
                                                                                                                                                    if (a2 == 0) {
                                                                                                                                                        v5 = 16;
                                                                                                                                                        src += v5;
                                                                                                                                                        src = (__int64 *)((__int64)(__int64)src & (__int64)a1);
                                                                                                                                                        xmm0 = _mm_loadu_si128((__m128i *)((__int64)result + (__int64)src));
                                                                                                                                                        a2 = _mm_movemask_epi8(xmm0);
                                                                                                                                                        v5 += 16;
                                                                                                                                                        while (a2 == 0) {
                                                                                                                                                        }
                                                                                                                                                    }
                                                                                                                                                    a2 = __builtin_ctz(a2);
                                                                                                                                                    a2 = (size_t *)((__int64)a2 + (__int64)src);
                                                                                                                                                    a2 = (size_t *)((__int64)(__int64)a2 & (__int64)a1);
                                                                                                                                                    v5 = *(__int64 *)((__int64)result + (__int64)a2);
                                                                                                                                                    if (v5 >= 0) {
                                                                                                                                                        xmm0 = _mm_load_si128((__m128i *)result);
                                                                                                                                                        a2 = _mm_movemask_epi8(xmm0);
                                                                                                                                                        a2 = __builtin_ctz(a2);
                                                                                                                                                        v5 = *(__int64 *)((__int64)result + (__int64)a2);
                                                                                                                                                    }
                                                                                                                                                    v6 = a2 - 16;
                                                                                                                                                    v6 &= (__int64)a1;
                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = v11;
                                                                                                                                                    *(result + v6 + 16) = v11;
                                                                                                                                                    a2 = (size_t *)((__int64)(__int64)a2 << 4);
                                                                                                                                                    a1 = (size_t *)result;
                                                                                                                                                    a1 = (size_t *)((__int64)a1 - (__int64)a2);
                                                                                                                                                    v5 &= 1;
                                                                                                                                                    v_10 = (__int64)src2;
                                                                                                                                                    v_c = (__int64)src2;
                                                                                                                                                    v_4 = (int *)v10;
                                                                                                                                                    a2 = (size_t *)(-(__int64)a2);
                                                                                                                                                    v6 = v_5a;
                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2 - 1) = v6;
                                                                                                                                                    result = (__int64 *)v_58;
                                                                                                                                                    v_3 = (__int64)result;
                                                                                                                                                    xmm0 = _mm_load_si128((__m128i *)&v_70);
                                                                                                                                                    result = (__int64 *)v5;
                                                                                                                                                    xmm1 = _mm_cvtsi32_si128(v5);
                                                                                                                                                    /* shufps $228, %xmm7, %xmm1 */;
                                                                                                                                                    xmm0 = _mm_sub_epi64(xmm0, xmm1);
                                                                                                                                                    _mm_store_si128((__m128i *)&v_70, xmm0);
                                                                                                                                                    result = src3;
                                                                                                                                                    if (v_48 != 0) {
                                                                                                                                                        off_140108030(a1, a2, v5);
                                                                                                                                                        off_140108038(result, 0, ptr);
                                                                                                                                                    }
                                                                                                                                                    a1 = (size_t *)v_60;
                                                                                                                                                    a2 = (size_t *)v_68;
                                                                                                                                                    result = (__int64 *)v_78;
                                                                                                                                                    xmm0 = _mm_load_si128((__m128i *)a1);
                                                                                                                                                    if (a2 == 0) {
                                                                                                                                                        dst3 = 0;
                                                                                                                                                    } else {
                                                                                                                                                        dst3 = (__int64 *)a2;
                                                                                                                                                        dst3 = (__int64 *)((__int64)(__int64)dst3 << 4);
                                                                                                                                                        v5 = (__int64)dst3 + (__int64)a2;
                                                                                                                                                        v5 += 33;
                                                                                                                                                        v6 = (__int64)a1;
                                                                                                                                                        v6 -= (__int64)dst3;
                                                                                                                                                        v6 -= 16;
                                                                                                                                                        dst3 = 16;
                                                                                                                                                    }
                                                                                                                                                    ptr = (struct Struct_1_t *)v_160;
                                                                                                                                                    dst2 = a1 + 16;
                                                                                                                                                    dst = _mm_movemask_epi8(xmm0);
                                                                                                                                                    dst = (__int64 *)(~(__int64)dst);
                                                                                                                                                    a2 = (size_t *)((__int64)a2 + (__int64)a1);
                                                                                                                                                    ++a2;
                                                                                                                                                    v_208 = (__int64)dst3;
                                                                                                                                                    v_210 = v5;
                                                                                                                                                    v_218 = v6;
                                                                                                                                                    v_220 = (int)a1;
                                                                                                                                                    v_228 = (__int64)dst2;
                                                                                                                                                    v_230 = (int)a2;
                                                                                                                                                    v_238 = (__int64)dst;
                                                                                                                                                    v_240 = (__int64)result;
                                                                                                                                                    a2 = rsp + 520;
                                                                                                                                                    sub_14008A830(ptr, a2, v5);
                                                                                                                                                    a2 = ptr->field_10;
                                                                                                                                                    if (a2 >= 2) {
                                                                                                                                                        a1 = ptr->field_8;
                                                                                                                                                        if (a2 >= 21) {
                                                                                                                                                            sub_14008B890();
                                                                                                                                                        } else {
                                                                                                                                                            result = a2 + (__int64)(__int64)a2*2;
                                                                                                                                                            result = a1 + (__int64)(__int64)result*4;
                                                                                                                                                            v6 = a1 + 12;
                                                                                                                                                            a2 = 12;
                                                                                                                                                            dst3 = (__int64 *)a1;
                                                                                                                                                            do {
                                                                                                                                                                v5 = v6;
                                                                                                                                                                v6 = *(dst3 + 12);
                                                                                                                                                                v6 = v5 + 12;
                                                                                                                                                                a2 += 12;
                                                                                                                                                                dst3 = (__int64 *)v5;
                                                                                                                                                            } while (v6 != result);
                                                                                                                                                        }
                                                                                                                                                    }
                                                                                                                                                    a1 = (size_t *)v_1e8;
                                                                                                                                                    if (a1 != 0) {
                                                                                                                                                        result =  + (__int64)(__int64)a1*4 + 19;
                                                                                                                                                        result = (__int64 *)((__int64)(__int64)result & -16);
                                                                                                                                                        a1 = (size_t *)((__int64)a1 + (__int64)result);
                                                                                                                                                        if (a1 != -17) {
                                                                                                                                                            dst = (__int64 *)v_1e0;
                                                                                                                                                            dst = (__int64 *)((__int64)dst - (__int64)result);
                                                                                                                                                            off_140108030(a1, a2);
                                                                                                                                                            off_140108038(result, 0, dst);
                                                                                                                                                        }
                                                                                                                                                    }
                                                                                                                                                    xmm6 = _mm_load_si128((__m128i *)&v_260);
                                                                                                                                                    xmm7 = _mm_load_si128((__m128i *)&v_270);
                                                                                                                                                    return _mm_cvtsi128_si64(xmm7);
                                                                                                                                                }
                                                                                                                                                v6 += v5;
                                                                                                                                                v6 += 16;
                                                                                                                                                v5 += 16;
                                                                                                                                            } while (true);
                                                                                                                                        }
                                                                                                                                    }
                                                                                                                                    return v5;
                                                                                                                                }
                                                                                                                                v11 = v_f8;
                                                                                                                                off_140108030();
                                                                                                                                off_140108038(result, 0, v11);
                                                                                                                                return v11;
                                                                                                                            }
                                                                                                                            off_140108030();
                                                                                                                            v5 = v_1a8;
                                                                                                                            off_140108038(result, 0, v5);
                                                                                                                            return v5;
                                                                                                                        }
                                                                                                                        off_140108030();
                                                                                                                        v5 = v_48;
                                                                                                                        off_140108038(result, 0, v5);
                                                                                                                        return v5;
                                                                                                                    }
                                                                                                                    src2 = (__int64 *)v_48;
                                                                                                                    v10 =  + v10*4;
                                                                                                                    v10 += (__int64)src2;
                                                                                                                    for (; src2 != v10; src2 += 4) {
                                                                                                                        ptr = *src2;
                                                                                                                        if (i2 == v_170) {
                                                                                                                            a1 = rsp + 368;
                                                                                                                            sub_1400FAB20(a1, a2, 0, v6);
                                                                                                                            dst = (__int64 *)v_178;
                                                                                                                        }
                                                                                                                        dst[i2] = ptr;
                                                                                                                        *(dst + i2*8 + 4) = 2;
                                                                                                                        ++i2;
                                                                                                                        v_180 = i2;
                                                                                                                    }
                                                                                                                    return (__int64)src2;
                                                                                                                }
                                                                                                                v_47 = (int)a2;
                                                                                                                a2 = *result;
                                                                                                                result += 9;
                                                                                                                a1 = (size_t *)arg_2;
                                                                                                                v_5e = (int)a1;
                                                                                                                result = *result;
                                                                                                                v_5c = (__int64)result;
                                                                                                                if (v_140 == 0) {
                                                                                                                    a1 = rsp + 304;
                                                                                                                    ptr = (struct Struct_1_t *)a2;
                                                                                                                    a2 = rsp + 336;
                                                                                                                    sub_1400FA650(a1, a2);
                                                                                                                }
                                                                                                                v6 = (__int64)a2;
                                                                                                                result = 0xF1357AEA2E62A9C5;
                                                                                                                v6 *= (__int64)result;
                                                                                                                v6 = __ROL8__(v6, 26);
                                                                                                                dst2 = (__int64 *)v_130;
                                                                                                                src2 = (__int64 *)v_138;
                                                                                                                a1 = (size_t *)v6;
                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 >> 57);
                                                                                                                xmm0 = _mm_cvtsi32_si128(a1);
                                                                                                                xmm0 = _mm_unpacklo_epi8(xmm0, xmm0);
                                                                                                                xmm0 = _mm_shufflelo_epi16(xmm0, 0);
                                                                                                                xmm0 = _mm_shuffle_epi32(xmm0, 68);
                                                                                                                result = 0;
                                                                                                                ptr = 0;
                                                                                                                do {
                                                                                                                    v6 &= (__int64)src2;
                                                                                                                    xmm1 = _mm_loadu_si128((__m128i *)(dst2 + v6));
                                                                                                                    xmm2 = xmm1;
                                                                                                                    xmm2 = _mm_cmpeq_epi8(xmm2, xmm0);
                                                                                                                    dst3 = _mm_movemask_epi8(xmm2);
                                                                                                                    if (result == 1) {
                                                                                                                        xmm1 = _mm_cmpeq_epi8(xmm1, xmm6);
                                                                                                                        result = _mm_movemask_epi8(xmm1);
                                                                                                                        if (result != 0) {
                                                                                                                            v6 = *(dst2 + v5);
                                                                                                                            if (v6 >= 0) {
                                                                                                                                xmm0 = _mm_load_si128((__m128i *)dst2);
                                                                                                                                result = _mm_movemask_epi8(xmm0);
                                                                                                                                v5 = __builtin_ctz(result);
                                                                                                                                v6 = *(dst2 + v5);
                                                                                                                            }
                                                                                                                            v6 &= 1;
                                                                                                                            result = v5 - 16;
                                                                                                                            result = (__int64 *)((__int64)(__int64)result & (__int64)src2);
                                                                                                                            *(dst2 + v5) = a1;
                                                                                                                            *(__int64 *)((__int64)dst2 + (__int64)result + 16) = a1;
                                                                                                                            xmm0 = _mm_load_si128((__m128i *)&v_140);
                                                                                                                            result = (__int64 *)v6;
                                                                                                                            xmm1 = _mm_cvtsi32_si128(result);
                                                                                                                            /* shufps $228, %xmm7, %xmm1 */;
                                                                                                                            xmm0 = _mm_sub_epi64(xmm0, xmm1);
                                                                                                                            _mm_store_si128((__m128i *)&v_140, xmm0);
                                                                                                                            ptr = (struct Struct_1_t *)v5;
                                                                                                                            ptr = (struct Struct_1_t *)(-(__int64)ptr);
                                                                                                                            v5 <<= 4;
                                                                                                                            result = dst2;
                                                                                                                            result -= v5;
                                                                                                                            v5 = -v5;
                                                                                                                            *(dst2 + v5 - 16) = a2;
                                                                                                                            v_c = (__int64)a2;
                                                                                                                            a1 = (size_t *)v_47;
                                                                                                                            v_4 = (int *)a1;
                                                                                                                            ptr = (struct Struct_1_t *)((__int64)(__int64)ptr << 4);
                                                                                                                            result = (__int64 *)v_5e;
                                                                                                                            *(__int64 *)((__int64)dst2 + (__int64)ptr - 1) = result;
                                                                                                                            result = (__int64 *)v_5c;
                                                                                                                            *(__int64 *)((__int64)dst2 + (__int64)ptr - 3) = result;
                                                                                                                            return (__int64)result;
                                                                                                                        }
                                                                                                                        result = 1;
                                                                                                                        v6 += (__int64)ptr;
                                                                                                                        v6 += 16;
                                                                                                                        ptr += 16;
                                                                                                                    }
                                                                                                                    result = _mm_movemask_epi8(xmm1);
                                                                                                                    if (result == 0) {
                                                                                                                        result = 0;
                                                                                                                        return (__int64)result;
                                                                                                                    }
                                                                                                                    v5 = __builtin_ctz(result);
                                                                                                                    v5 += v6;
                                                                                                                    v5 &= (__int64)src2;
                                                                                                                    return v5;
                                                                                                                } while (true);
                                                                                                            }
                                                                                                            if (v_158 == a2) {
                                                                                                                return v5;
                                                                                                            }
                                                                                                            result = src3;
                                                                                                            result = (__int64 *)((__int64)(__int64)(__int64)result * (__int64)a1); /* unsigned; high half in a2 */;
                                                                                                            src3 = (__int64 *)a2;
                                                                                                            src3 = (__int64 *)((__int64)(__int64)src3 >> 5);
                                                                                                            do {
                                                                                                                src += 40;
                                                                                                                --src3;
                                                                                                            } while (!((src3 == 0)));
                                                                                                            return (__int64)src3;
                                                                                                        }
                                                                                                        result = rsp + 464;
                                                                                                        v_d0 = (__int64)result;
                                                                                                        result = &off_140018400;
                                                                                                        v_d8 = (__int64)result;
                                                                                                        a1 = rsp + 472;
                                                                                                        v_e0 = (int)a1;
                                                                                                        v_e8 = (__int64)result;
                                                                                                        result = &off_1401178A8;
                                                                                                        v_80 = (__int64)result;
                                                                                                        v_88 = 2;
                                                                                                        v_a0 = 0;
                                                                                                        result = rsp + 208;
                                                                                                        v_90 = (__int64)result;
                                                                                                        v_98 = 2;
                                                                                                        a2 = &off_140117930;
                                                                                                        a1 = rsp + 128;
                                                                                                        sub_1400F37A0(a1, a2);
                                                                                                        return (__int64)a1;
                                                                                                    }
                                                                                                    result += 272;
                                                                                                    return (__int64)result;
                                                                                                }
                                                                                                a1 = &off_140117948;
                                                                                                v5 = &off_140117978;
                                                                                                sub_1400F37D0(a1, 47, v5);
                                                                                                return v5;
                                                                                            }
                                                                                            return v5;
                                                                                        }
                                                                                        v_48 = v5;
                                                                                        result = 1;
                                                                                        v6 += (__int64)dst2;
                                                                                        v6 += 16;
                                                                                        dst2 += 16;
                                                                                    }
                                                                                    v5 = _mm_movemask_epi8(xmm1);
                                                                                    if (v5 == 0) {
                                                                                        result = 0;
                                                                                        return (__int64)result;
                                                                                    }
                                                                                    v5 = __builtin_ctz(v5);
                                                                                    v5 += v6;
                                                                                    v5 &= (__int64)a2;
                                                                                    return v5;
                                                                                } while (true);
                                                                            } while (i2 != dst);
                                                                            return v5;
                                                                        } while (dst != 0);
                                                                        return v5;
                                                                    } else {
                                                                        v_d0 = 0;
                                                                        v_d8 = 4;
                                                                        v_e0 = 0;
                                                                    }
                                                                    return v_e0;
                                                                }
                                                                dst2 = 1;
                                                                v6 += (__int64)dst3;
                                                                v6 += 16;
                                                                dst3 += 16;
                                                            }
                                                            result = _mm_movemask_epi8(xmm1);
                                                            if (result == 0) {
                                                                dst2 = 0;
                                                                return (__int64)dst2;
                                                            }
                                                            i2 = __builtin_ctz(result);
                                                            i2 += v6;
                                                            i2 &= (__int64)a2;
                                                            return i2;
                                                        } while (true);
                                                    }
                                                }
                                                return i2;
                                            }
                                            src3 = *(__int64 *)(ptr + i2);
                                            if (src3 <= src2) {
                                                return (__int64)src3;
                                            }
                                            if (a2 != v_80) {
                                                a1 = a2 + (__int64)(__int64)a2*2;
                                                v_0[(__int64)a1] = src2;
                                                v_4[(__int64)a1] = src3;
                                                v_8[(__int64)a1] = 0;
                                                ++a2;
                                                v_90 = (__int64)a2;
                                                return v_90;
                                            }
                                            v10 = (__int64)a2;
                                            sub_1400FA0D0(src, a2);
                                            a2 = (size_t *)v10;
                                            result = (__int64 *)v_88;
                                            return (__int64)result;
                                        } while (v11 != i2);
                                        return (__int64)result;
                                    } else {
                                        xmm0 = _mm_loadu_si128((__m128i *)&off_14011D5E0);
                                        _mm_store_si128((__m128i *)&v_90, xmm0);
                                        xmm0 = _mm_loadu_si128((__m128i *)&off_14011D5D0);
                                        _mm_store_si128((__m128i *)&v_80, xmm0);
                                        ptr = 4;
                                        src2 = 1;
                                        v_c8 = 0;
                                        result = 4;
                                        v_48 = (__int64)result;
                                    }
                                    return v_48;
                                }
                                return v_48;
                            }
                        }
                    }
                }
            }
        }
    }
    return (__int64)result;
}