// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[16];
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
};

__int64 sub_14003D132();
__int64 sub_14003982C();
__int64 off_1401081D8();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140113788;
extern __int64 off_14003F420;

__int64 __fastcall sub_1400396B0() {
    int arg_3d8;
    int arg_3e0;
    int arg_4a8;
    int arg_4d0;
    int arg_4e0;
    int arg_548;
    int arg_550;
    int arg_568;
    int v_10;
    int v_20;
    int v_8;
    __m128i xmm0;
    __int64 result;
    __int64 *src;
    __int64 v13;
    __int64 v10;
    struct Struct_1_t *ptr;
    __int64 v11;
    __int64 v12;
    __int64 i;
    __int64 v7;
    __int64 v8;
    __int64 v4;
    __int64 *dst;

    xmm0 = _mm_loadu_si128((__m128i *)&arg_4d0);
    _mm_storeu_si128((__m128i *)&v_10, xmm0);
    result = arg_4e0;
    *dst = result;
    src = (__int64 *)arg_3d8;
    result = v_8;
    arg_548 = result;
    if (src == 0) {
        v13 = 0;
    } else {
        result = *dst;
        arg_568 = result;
        v10 = arg_3e0;
        v13 = 0;
        do {
            ptr = src + 360;
            v11 = *(src + 978);
            v12 = v11 * 56;
            i = -1;
            while (v12 != 0) {
                v7 = ptr->field_28;
                v8 = ptr->field_30;
                v_20 = 1;
                v4 = arg_568;
                off_1401081D8(arg_548, v4, v7, v8);
                ++i;
                if (result == 1) {
                    --v10;
                    ptr = (struct Struct_1_t *)arg_4a8;
                    if ((v10 < 0)) JUMPOUT(0x140039db2);
                    src = *(src + i*8 + 984);
                }
                if (result != 2) {
                    ptr += 56;
                    v12 -= 56;
                    return sub_14003D132();
                }
                i <<= 5;
                v13 = *(src + i + 8);
                result = *(src + i + 16);
                arg_568 = result;
                ptr = (struct Struct_1_t *)arg_4a8;
                i = arg_550;
                off_140108030();
                off_140108038(result, 0, i);
                if (v_10 != 0) {
                    off_140108030();
                    off_140108038(result, 0, arg_548);
                }
                i = ptr->field_10;
                src = &off_140113788;
                if (i == 0) JUMPOUT(0x14003ac5d);
                v4 = ptr->field_8;
                if (i >= 4) JUMPOUT(0x140039805);
                result = &off_14003F420;
                return sub_14003982C();
            }
            i = v11;
            return i;
        } while (true);
    }
    return result;
}