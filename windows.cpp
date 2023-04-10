//
// Created by Andrew on 10/04/2023.
//

#include <windows.h>
#include <commctrl.h>
#include <mmsystem.h>
#include <objidl.h>
#include <gdiplus.h>

#include "header.h"
#include "resource.h"

HWND hMainWindow;

const WCHAR *pAboutLink = L"http://github.com/Endermanch/XPKeygen";

void InitializeFonts(HFONT *hLabelFont, HFONT *hSmolFont, HFONT *hBoldFont, HFONT *hCaptionFont) {
    NONCLIENTMETRICSW nonClientMetrics;

    // Get information about the default system font.
    nonClientMetrics.cbSize = sizeof(NONCLIENTMETRICSW);
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(NONCLIENTMETRICSW), &nonClientMetrics, 0);

    ULONG defaultHeight = nonClientMetrics.lfMessageFont.lfHeight;

    // Create default font.
    *hLabelFont = CreateFontIndirectW(&nonClientMetrics.lfMessageFont);

    // Create smol font.
    nonClientMetrics.lfMessageFont.lfHeight = 12;
    *hSmolFont = CreateFontIndirectW(&nonClientMetrics.lfMessageFont);

    // Create bold font.
    nonClientMetrics.lfMessageFont.lfWeight = 700;
    nonClientMetrics.lfMessageFont.lfHeight = defaultHeight;
    *hBoldFont = CreateFontIndirectW(&nonClientMetrics.lfMessageFont);

    // Create caption font.
    nonClientMetrics.lfMessageFont.lfHeight = 30;
    *hCaptionFont = CreateFontIndirectW(&nonClientMetrics.lfMessageFont);
}

bool PlayAudio(HINSTANCE hInstance, WCHAR *lpName, UINT bFlags) {
    HANDLE hResInfo = FindResourceW(hInstance, lpName, L"WAVE");
    
    if (hResInfo == nullptr)
        return false;

    HANDLE hRes = LoadResource(hInstance, (HRSRC)hResInfo);
    
    if (hRes == nullptr)
        return false;

    WCHAR *lpRes = (WCHAR *)LockResource(hRes);
    FreeResource(hRes);

    return sndPlaySoundW(lpRes, SND_MEMORY | bFlags);
}

LRESULT CALLBACK WNDProc(HWND hWindow, UINT uMessage, WPARAM wParam, LPARAM lParam) {

    switch (uMessage) {
    case WM_CREATE:
        break;

    case WM_CTLCOLORSTATIC:
        if ((HWND)lParam == GetDlgItem(hWindow, IDC_EDIT1)) {
            SetBkMode((HDC)wParam, TRANSPARENT);
            SetTextColor((HDC)wParam, RGB(255, 255, 0));
            return (LRESULT)((HBRUSH)GetStockObject(BLACK_BRUSH));
        }
        else goto execute;

        break;

    case WM_CHAR:
        if (LOWORD(wParam) == VK_TAB)
            SetFocus(GetNextDlgTabItem(hWindow, NULL, FALSE));
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
            case IDC_BUTTON1: {
                ShellExecuteW(hWindow, L"open", pAboutLink, nullptr, nullptr, SW_SHOWNORMAL); 
                
                break;
            }

            case IDC_BUTTON2: {
                HWND hEdit = GetDlgItem(hMainWindow, IDC_EDIT1);
                HWND hInput1 = GetDlgItem(hMainWindow, IDC_INPUT1);
                HWND hInput2 = GetDlgItem(hMainWindow, IDC_INPUT2);

                WCHAR pBSection[4]{}, pCSection[8]{}, pFPK[32]{};

                SendMessageW(hInput1, WM_GETTEXT, 3 + NULL_TERMINATOR, (LPARAM)pBSection);
                SendMessageW(hInput2, WM_GETTEXT, 6 + NULL_TERMINATOR, (LPARAM)pCSection);

                int pSSection = 0;

                for (int i = 0; i < 6; i++)
                    pSSection -= pCSection[i] - '0';

                while (pSSection < 0)
                    pSSection += 7;

                ul32 msDigits = _wtoi(pBSection),
                     lsDigits = _wtoi(pCSection);

                ul32 nRPK = msDigits * 1'000'000 + lsDigits,
                     hash = 0,
                     sig[2]{};

                CHAR pKey[PK_LENGTH + NULL_TERMINATOR]{};

                keyXP(pKey, &hash, sig, nRPK);

                for (int i = 0; i < 5; i++)
                    wsprintfW(pFPK, L"%s%s%.5S", pFPK, i != 0 ? L"-" : L"", &pKey[5 * i]);

                WCHAR *pText = (WCHAR *)calloc(512 + 4 + 9 + 5 * NULL_TERMINATOR, sizeof(WCHAR));

                wsprintfW(
                    pText,
                    L"%s%sProduct ID: PPPPP-%03d-%06d%d-23XXX\r\nHash: %08lX\r\nSignature: %08lX-%08lX\r\n\r\n%s\r\n",
                    pText,
                    wcslen(pText) ? L"\r\n" : L"",
                    nRPK / 1'000'000,
                    nRPK % 1'000'000,
                    pSSection,
                    hash,
                    sig[1], sig[0],
                    pFPK
                );            

                SendMessageW(hEdit, WM_SETTEXT, 0, (LPARAM)pText);

                free(pText);

                return 0;
            }

            case IDC_BUTTON3: {
                DestroyWindow(hWindow);
                return 0;
            }

            case IDC_BUTTON4: {

                break;
            }
        }
        
        
        break;

    case WM_CLOSE:
        DestroyWindow(hWindow);

        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    execute:
    default:
        return DefWindowProc(hWindow, uMessage, wParam, lParam);
    }

    return 0;
}


bool InitializeWindow(HINSTANCE hInstance) {
    HFONT   hLabelFont,
            hSmolFont,
            hCaptionFont,
            hBoldFont;

    WNDCLASSEX wndClass{};

    // Register the main window class.
    wndClass.cbSize = sizeof(WNDCLASSEX);
    wndClass.hInstance = hInstance;
    wndClass.lpfnWndProc = (WNDPROC)WNDProc;
    wndClass.lpszClassName = L"XPKeygen";
    wndClass.hbrBackground = (HBRUSH)COLOR_WINDOW;
    wndClass.style = CS_HREDRAW | CS_VREDRAW;
    wndClass.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(IDI_ICON1));
    wndClass.hIconSm = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_ICON1));
    wndClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);

    if (!RegisterClassExW(&wndClass))
        return false;

    InitializeFonts(&hLabelFont, &hSmolFont, &hBoldFont, &hCaptionFont);

    const int   w = 615,
                h = 480,
                x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2,
                y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;

    hMainWindow = CreateWindowExW(
            0,
            L"XPKeygen",
            L"Windows XP VLK // Server 2003 - Enderman[ch]",
            WS_SYSMENU,
            x, y,
            w, h,
            nullptr,
            nullptr,
            hInstance,
            nullptr
    );

    HDC hMainDC = GetDC(hMainWindow);

    // Select the default font.
    SelectObject(hMainDC, hLabelFont);

    HBITMAP hBitmap = (HBITMAP)LoadImageW(hInstance, MAKEINTRESOURCEW(IDB_BITMAP2), IMAGE_BITMAP, 0, 0, 0);

    HWND hLogo = CreateWindowExW(
        0,
        L"Static", nullptr,
        WS_CHILD | WS_VISIBLE |
        SS_BITMAP | SS_REALSIZEIMAGE,
        0, 0,
        600, 0,
        hMainWindow, (HMENU)IDC_IMAGE1,
        hInstance, nullptr
    );

    SendMessageW(hLogo, STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)hBitmap);

    HWND hGroupBox = CreateWindowExW(
        0,
        L"Button", L"Windows XP Pro VLK x86 // Server 2003 + SP2 x64",
        WS_CHILD | WS_VISIBLE |
        BS_GROUPBOX,
        10, 150,
        w - 36, h - 200,
        hMainWindow, nullptr,
        hInstance, nullptr
    );

    SendMessageW(hGroupBox, WM_SETFONT, (WPARAM)hCaptionFont, 0);

    HWND hRPKLabel = CreateWindowExW(
        0,
        L"Static", L"Raw Product Key:",
        WS_CHILD | WS_VISIBLE,
        20, 190,
        100, 16,
        hMainWindow, nullptr,
        hInstance, nullptr
    );

    SendMessageW(hRPKLabel, WM_SETFONT, (WPARAM)hBoldFont, 0);

    HWND hInput1 = CreateWindowExW(
        0,
        L"Edit",
        L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP |
        ES_LEFT | ES_NUMBER,
        130, 189,
        40, 20,
        hMainWindow,
        (HMENU)IDC_INPUT1,
        hInstance,
        nullptr
    );

    SendMessageW(hInput1, EM_SETCUEBANNER, 0, (LPARAM)L"BBB");
    SendMessageW(hInput1, WM_SETFONT, (WPARAM)hLabelFont, 0);

    SendMessageW(hInput1, EM_SETLIMITTEXT, (WPARAM)3, 0);

    HWND hRPKDash = CreateWindowExW(
        0,
        L"Static", L"-",
        WS_CHILD | WS_VISIBLE,
        173, 190,
        10, 16,
        hMainWindow, nullptr,
        hInstance, nullptr
    );

    SendMessageW(hRPKDash, WM_SETFONT, (WPARAM)hBoldFont, 0);

    HWND hInput2 = CreateWindowExW(
        0,
        L"Edit",
        L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP |
        ES_LEFT | ES_NUMBER,
        181, 189,
        70, 20,
        hMainWindow,
        (HMENU)IDC_INPUT2,
        hInstance,
        nullptr
    );

    SendMessageW(hInput2, EM_SETCUEBANNER, 0, (LPARAM)L"CCCCCC");
    SendMessageW(hInput2, WM_SETFONT, (WPARAM)hLabelFont, 0);

    SendMessageW(hInput2, EM_SETLIMITTEXT, (WPARAM)6, 0);

    HWND hRandomize = CreateWindowExW(
        0,
        L"Button",
        L"Randomize",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        260, 188,
        75, 22,
        hMainWindow,
        (HMENU)IDC_BUTTON4,
        hInstance,
        nullptr
    );

    SendMessageW(hRandomize, WM_SETFONT, (WPARAM)hLabelFont, 0);

    HWND hVersionLabel = CreateWindowExW(
        0,
        L"Static", L"Version:",
        WS_CHILD | WS_VISIBLE,
        20, 220,
        100, 16,
        hMainWindow, nullptr,
        hInstance, nullptr
    );

    SendMessageW(hVersionLabel, WM_SETFONT, (WPARAM)hBoldFont, 0);

    HWND hRadio1 = CreateWindowExW(
        WS_EX_WINDOWEDGE,
        L"Button",
        L"Windows XP VLK",
        WS_VISIBLE | WS_CHILD | WS_GROUP |
        BS_AUTORADIOBUTTON,
        70, 219,
        120, 20,
        hMainWindow,
        (HMENU)IDC_RADIO1,
        hInstance, NULL
    );

    SendMessageW(hRadio1, BM_SETCHECK, 1, 0);
    SendMessageW(hRadio1, WM_SETFONT, (WPARAM)hLabelFont, 0);

    HWND hRadio2 = CreateWindowExW(
        WS_EX_WINDOWEDGE,
        L"Button",
        L"Windows Server 2003 / SP2 x64",
        WS_VISIBLE | WS_CHILD |
        BS_AUTORADIOBUTTON,
        200, 219,
        180, 20,
        hMainWindow,
        (HMENU)IDC_RADIO2,
        hInstance, NULL);

    SendMessageW(hRadio2, WM_SETFONT, (WPARAM)hLabelFont, 0);

    HWND hEdit = CreateWindowExW(
        0,
        L"Edit",
        L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | 
        ES_MULTILINE | ES_READONLY |
        ES_LEFT | ES_UPPERCASE,
        20, 250,
        w - 57, h - 350,
        hMainWindow,
        (HMENU)IDC_EDIT1,
        hInstance,
        nullptr
    );

    SendMessageW(hEdit, WM_SETFONT, (WPARAM)hBoldFont, 0);

    HWND hInfo = CreateWindowExW(
        0,
        L"Button",
        L"About",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        44, h - 90,
        100, 27,
        hMainWindow,
        (HMENU)IDC_BUTTON1,
        hInstance,
        nullptr
    );

    SendMessageW(hInfo, WM_SETFONT, (WPARAM)hLabelFont, 0);

    HWND hGenerate = CreateWindowExW(
        0,
        L"Button",
        L"Generate",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP |
        BS_PUSHBUTTON,
        250, h - 90,
        100, 27,
        hMainWindow,
        (HMENU)IDC_BUTTON2,
        hInstance,
        nullptr
    );

    SendMessageW(hGenerate, WM_SETFONT, (WPARAM)hLabelFont, 0);

    HWND hQuit = CreateWindowExW(
        0,
        L"Button",
        L"Quit",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        w - 160, h - 90,
        100, 27,
        hMainWindow,
        (HMENU)IDC_BUTTON3,
        hInstance,
        nullptr
    );

    SendMessageW(hQuit, WM_SETFONT, (WPARAM)hLabelFont, 0);
    
    ShowWindow(hMainWindow, SW_SHOW);
    UpdateWindow(hMainWindow);

    PlayAudio(hInstance, MAKEINTRESOURCEW(IDR_WAVE1), SND_ASYNC | SND_LOOP | SND_NODEFAULT);

    MSG uMessage;

    while(GetMessageW(&uMessage, nullptr, 0, 0)) {
        TranslateMessage(&uMessage);
        DispatchMessageW(&uMessage);
    }

    ReleaseDC(hMainWindow, hMainDC);

    return true;
}