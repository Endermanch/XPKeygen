#pragma once

enum VERSIONS {
    W98SE,
    W98SEOEM,
    WXP,
    WXPOEM,
    WSERVER2003,
    WXP64,
    WXP64OEM,
    WCOUNT
};

extern const wchar_t *pPresets[256];
extern const char *p[256];
extern const char *a;
extern const char *b;
extern const char *gx[256];
extern const char *gy[256];

extern const char *kx[256];

extern const char *ky[256];

extern const unsigned long long generatorOrderArr[];

extern const unsigned long long privateKeyArr[];
