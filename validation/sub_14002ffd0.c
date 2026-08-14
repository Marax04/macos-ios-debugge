extern __int64 off_140121930;
extern __int64 off_140121508;

__int64 __fastcall sub_14002FFD0(size_t a1) {
    __int64 result;
    __int64 v2;

    result = 1;
    if (a1 > 0x460) {
        if (a1 <= 0x271C) {
            if (a1 > 0x780) {
                if (a1 <= 0x1B7F) {
                    if (a1 == 0x781) {
                        result = 18;
                        return result;
                    } else {
                        if (a1 != 0x1716) {
                            if (a1 != 0x1B64) {
                                result = 41;
                                return result;
                            }
                        }
                    }
                } else {
                    if (a1 > 0x2021) {
                        if (a1 != 0x2022) {
                            if (a1 != 0x25E9) {
                                return result;
                            }
                        }
                    } else {
                        if (a1 != 0x1B80) {
                            if (a1 != 0x1F4E) {
                                return result;
                            }
                        }
                    }
                }
            } else {
                if (a1 <= 0x4CE) {
                    if (a1 != 0x461) {
                        if (a1 == 0x46B) {
                            result = 30;
                            return result;
                        } else {
                            if (a1 != 0x476) {
                                return result;
                            } else {
                                result = 32;
                                return result;
                            }
                        }
                    }
                } else {
                    if (a1 > 0x50E) {
                        if (a1 == 0x50F) {
                            result = 26;
                            return result;
                        } else {
                            if (a1 == 0x5B4) {
                                result = 22;
                                return result;
                            } else {
                            }
                        }
                    } else {
                        if (a1 == 0x4CF) {
                            result = 5;
                            return result;
                        } else {
                            if (a1 == 0x4D0) {
                                result = 4;
                                return result;
                            }
                        }
                    }
                    return result;
                }
            }
        } else {
            v2 = a1 - 0x271D;
            if (v2 <= 56) {
                a1 = &off_140121930;
                switch (v2) {
                    case 2:
                        return a1;
                    case 3:
                        return a1;
                    case 22:
                        result = 13;
                        return result;
                    case 35:
                        result = 8;
                        return result;
                    case 36:
                        result = 9;
                        return result;
                    case 37:
                        result = 10;
                        return result;
                    case 38:
                        return result;
                    case 40:
                        result = 6;
                        return result;
                    case 41:
                        result = 3;
                        return result;
                    case 44:
                        result = 7;
                        return result;
                    case 48:
                        result = 2;
                        return result;
                    case 52:
                        return result;
                    case 56:
                        return result;
                    case 85:
                        result = 20;
                        return result;
                    case 119:
                        return result;
                    default:
                        break;
                }
            }
            result = a1 - 0x3C2A;
            if (result >= 2) {
                if (a1 != 0x35ED) {
                    return result;
                }
            }
        }
    } else {
        if (a1 > 335) {
            if (a1 > 994) {
                if (a1 != 995) {
                    if (a1 != 0x41D) {
                        return result;
                    }
                }
            } else {
                if (a1 == 336) {
                    result = 15;
                    return result;
                } else {
                    if (a1 != 594) {
                        return result;
                    }
                }
            }
        } else {
            a1 += 0xFFFFFFFE;
            if (a1 <= 265) {
                v2 = &off_140121508;
                switch (a1) {
                    case 0:
                        result = 0;
                        return result;
                    case 2:
                        break;
                    case 3:
                        return result;
                    case 6:
                        result = 38;
                        return result;
                    case 15:
                        result = 31;
                        return result;
                    case 17:
                        result = 17;
                        return result;
                    case 37:
                        result = 24;
                        return result;
                    case 78:
                        result = 12;
                        return result;
                    case 85:
                        return result;
                    case 107:
                        result = 11;
                        return result;
                    case 118:
                        result = 36;
                        return result;
                    case 119:
                        return result;
                    case 121:
                        result = 33;
                        return result;
                    case 130:
                        result = 25;
                        return result;
                    case 143:
                        result = 16;
                        return result;
                    case 168:
                        result = 28;
                        return result;
                    case 221:
                        result = 27;
                        return result;
                    case 265:
                        result = 14;
                        return result;
                }
            }
            return result;
        }
    }
    return result;
}