"""
EDF5 Voice Hook — PoC
Hooks SoundController::PlayVoice and displays looked-up subtitles in an overlay.
If a cue ends with _E, it is normalized to the non-_E key before subtitle lookup.

Usage:
    python voice_hook.py
"""

import ctypes
import frida
import queue
import sys
import time
from ctypes import wintypes
from pathlib import Path

SUBTITLE_PATH = Path(__file__).with_name("subtitles.txt")
CUE_LENGTH_PATH = Path(__file__).with_name("cuelength.txt")
FALLBACK_DISPLAY_MS = 4500
MIN_DISPLAY_MS = 2200
TAIL_PADDING_MS = 450
WINDOW_ALPHA = 0.5
BG_COLOR = "#101218"
PV_COLOR = "#FFF0A6"
PS_COLOR = "#8FE7FF"
TOPMOST_REFRESH_MS = 1500
WINDOW_PAD_X = 18
WINDOW_PAD_Y = 14
WINDOW_MARGIN_X = 20
WINDOW_MARGIN_BOTTOM = 110
WINDOW_HIDDEN_HEIGHT = 1
TEXT_GAP_Y = 8
FONT_FACE = "Microsoft JhengHei UI"
FONT_POINT_SIZE = 24
FONT_WEIGHT_BOLD = 700
SUBTITLE_STACK_MAX = 3

IS_WINDOWS = sys.platform.startswith("win")

if IS_WINDOWS:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    LONG_PTR = ctypes.c_longlong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_long

    GWL_EXSTYLE = -20
    WS_POPUP = 0x80000000
    WS_EX_TOPMOST = 0x00000008
    WS_EX_TOOLWINDOW = 0x00000080
    WS_EX_LAYERED = 0x00080000
    WS_EX_NOACTIVATE = 0x08000000

    LWA_ALPHA = 0x00000002

    SWP_NOSIZE = 0x0001
    SWP_NOMOVE = 0x0002
    SWP_NOACTIVATE = 0x0010
    SWP_SHOWWINDOW = 0x0040

    WM_DESTROY = 0x0002
    WM_ERASEBKGND = 0x0014
    WM_PAINT = 0x000F
    WM_MOUSEACTIVATE = 0x0021
    WM_NCHITTEST = 0x0084
    HTTRANSPARENT = -1
    MA_NOACTIVATE = 3
    PM_REMOVE = 0x0001

    DT_CENTER = 0x00000001
    DT_WORDBREAK = 0x00000010
    DT_NOCLIP = 0x00000100
    DT_CALCRECT = 0x00000400
    DT_NOPREFIX = 0x00000800
    TRANSPARENT = 1

    SW_HIDE = 0
    SW_SHOWNOACTIVATE = 4

    LOGPIXELSY = 90

    GA_ROOT = 2
    MONITOR_DEFAULTTONEAREST = 2
    HWND_TOPMOST = wintypes.HWND(-1)
    SM_CXSCREEN = 0
    SM_CYSCREEN = 1

    if ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_long):
        GetWindowLongPtrW = user32.GetWindowLongW
        SetWindowLongPtrW = user32.SetWindowLongW
    else:
        GetWindowLongPtrW = user32.GetWindowLongPtrW
        SetWindowLongPtrW = user32.SetWindowLongPtrW

    GetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int]
    GetWindowLongPtrW.restype = LONG_PTR

    SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, LONG_PTR]
    SetWindowLongPtrW.restype = LONG_PTR

    SetLayeredWindowAttributes = user32.SetLayeredWindowAttributes
    SetLayeredWindowAttributes.argtypes = [
        wintypes.HWND,
        wintypes.COLORREF,
        wintypes.BYTE,
        wintypes.DWORD,
    ]
    SetLayeredWindowAttributes.restype = wintypes.BOOL

    SetWindowPos = user32.SetWindowPos
    SetWindowPos.argtypes = [
        wintypes.HWND,
        wintypes.HWND,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    SetWindowPos.restype = wintypes.BOOL

    GetAncestor = user32.GetAncestor
    GetAncestor.argtypes = [wintypes.HWND, ctypes.c_uint]
    GetAncestor.restype = wintypes.HWND

    MonitorFromWindow = user32.MonitorFromWindow
    MonitorFromWindow.argtypes = [wintypes.HWND, wintypes.DWORD]
    MonitorFromWindow.restype = wintypes.HANDLE

    class MONITORINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("rcMonitor", wintypes.RECT),
            ("rcWork", wintypes.RECT),
            ("dwFlags", wintypes.DWORD),
        ]

    GetMonitorInfoW = user32.GetMonitorInfoW
    GetMonitorInfoW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MONITORINFO)]
    GetMonitorInfoW.restype = wintypes.BOOL

    GetWindowRect = user32.GetWindowRect
    GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    GetWindowRect.restype = wintypes.BOOL

    GetWindowThreadProcessId = user32.GetWindowThreadProcessId
    GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    GetWindowThreadProcessId.restype = wintypes.DWORD

    IsWindow = user32.IsWindow
    IsWindow.argtypes = [wintypes.HWND]
    IsWindow.restype = wintypes.BOOL

    IsWindowVisible = user32.IsWindowVisible
    IsWindowVisible.argtypes = [wintypes.HWND]
    IsWindowVisible.restype = wintypes.BOOL

    EnumWindows = user32.EnumWindows
    EnumWindows.restype = wintypes.BOOL

    GetSystemMetrics = user32.GetSystemMetrics
    GetSystemMetrics.argtypes = [ctypes.c_int]
    GetSystemMetrics.restype = ctypes.c_int

    DrawTextW = user32.DrawTextW
    DrawTextW.argtypes = [wintypes.HDC, wintypes.LPCWSTR, ctypes.c_int, ctypes.POINTER(wintypes.RECT), ctypes.c_uint]
    DrawTextW.restype = ctypes.c_int

    FillRect = user32.FillRect
    FillRect.argtypes = [wintypes.HDC, ctypes.POINTER(wintypes.RECT), wintypes.HANDLE]
    FillRect.restype = ctypes.c_int

    InvalidateRect = user32.InvalidateRect
    InvalidateRect.argtypes = [wintypes.HWND, ctypes.c_void_p, wintypes.BOOL]
    InvalidateRect.restype = wintypes.BOOL

    ShowWindow = user32.ShowWindow
    ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    ShowWindow.restype = wintypes.BOOL

    UpdateWindow = user32.UpdateWindow
    UpdateWindow.argtypes = [wintypes.HWND]
    UpdateWindow.restype = wintypes.BOOL

    DestroyWindow = user32.DestroyWindow
    DestroyWindow.argtypes = [wintypes.HWND]
    DestroyWindow.restype = wintypes.BOOL

    GetDC = user32.GetDC
    GetDC.argtypes = [wintypes.HWND]
    GetDC.restype = wintypes.HDC

    ReleaseDC = user32.ReleaseDC
    ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
    ReleaseDC.restype = ctypes.c_int

    BeginPaint = user32.BeginPaint
    EndPaint = user32.EndPaint

    PeekMessageW = user32.PeekMessageW
    TranslateMessage = user32.TranslateMessage
    DispatchMessageW = user32.DispatchMessageW
    DefWindowProcW = user32.DefWindowProcW
    PostQuitMessage = user32.PostQuitMessage
    RegisterClassW = user32.RegisterClassW
    CreateWindowExW = user32.CreateWindowExW

    GetModuleHandleW = kernel32.GetModuleHandleW
    GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    GetModuleHandleW.restype = wintypes.HMODULE

    CreateSolidBrush = gdi32.CreateSolidBrush
    CreateSolidBrush.argtypes = [wintypes.COLORREF]
    CreateSolidBrush.restype = wintypes.HANDLE

    CreateFontW = gdi32.CreateFontW
    CreateFontW.restype = wintypes.HANDLE

    DeleteObject = gdi32.DeleteObject
    DeleteObject.argtypes = [wintypes.HANDLE]
    DeleteObject.restype = wintypes.BOOL

    SelectObject = gdi32.SelectObject
    SelectObject.argtypes = [wintypes.HDC, wintypes.HANDLE]
    SelectObject.restype = wintypes.HANDLE

    SetBkMode = gdi32.SetBkMode
    SetBkMode.argtypes = [wintypes.HDC, ctypes.c_int]
    SetBkMode.restype = ctypes.c_int

    SetTextColor = gdi32.SetTextColor
    SetTextColor.argtypes = [wintypes.HDC, wintypes.COLORREF]
    SetTextColor.restype = wintypes.COLORREF

    GetDeviceCaps = gdi32.GetDeviceCaps
    GetDeviceCaps.argtypes = [wintypes.HDC, ctypes.c_int]
    GetDeviceCaps.restype = ctypes.c_int

    WNDPROC = ctypes.WINFUNCTYPE(LONG_PTR, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

    class WNDCLASSW(ctypes.Structure):
        _fields_ = [
            ("style", wintypes.UINT),
            ("lpfnWndProc", WNDPROC),
            ("cbClsExtra", ctypes.c_int),
            ("cbWndExtra", ctypes.c_int),
            ("hInstance", wintypes.HINSTANCE),
            ("hIcon", wintypes.HANDLE),
            ("hCursor", wintypes.HANDLE),
            ("hbrBackground", wintypes.HANDLE),
            ("lpszMenuName", wintypes.LPCWSTR),
            ("lpszClassName", wintypes.LPCWSTR),
        ]

    class PAINTSTRUCT(ctypes.Structure):
        _fields_ = [
            ("hdc", wintypes.HDC),
            ("fErase", wintypes.BOOL),
            ("rcPaint", wintypes.RECT),
            ("fRestore", wintypes.BOOL),
            ("fIncUpdate", wintypes.BOOL),
            ("rgbReserved", ctypes.c_ubyte * 32),
        ]

    class POINT(ctypes.Structure):
        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

    class MSG(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("message", wintypes.UINT),
            ("wParam", wintypes.WPARAM),
            ("lParam", wintypes.LPARAM),
            ("time", wintypes.DWORD),
            ("pt", POINT),
            ("lPrivate", wintypes.DWORD),
        ]

    BeginPaint.argtypes = [wintypes.HWND, ctypes.POINTER(PAINTSTRUCT)]
    BeginPaint.restype = wintypes.HDC

    EndPaint.argtypes = [wintypes.HWND, ctypes.POINTER(PAINTSTRUCT)]
    EndPaint.restype = wintypes.BOOL

    PeekMessageW.argtypes = [ctypes.POINTER(MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT, wintypes.UINT]
    PeekMessageW.restype = wintypes.BOOL

    TranslateMessage.argtypes = [ctypes.POINTER(MSG)]
    TranslateMessage.restype = wintypes.BOOL

    DispatchMessageW.argtypes = [ctypes.POINTER(MSG)]
    DispatchMessageW.restype = LONG_PTR

    DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    DefWindowProcW.restype = LONG_PTR

    PostQuitMessage.argtypes = [ctypes.c_int]
    PostQuitMessage.restype = None

    RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
    RegisterClassW.restype = wintypes.ATOM

    CreateWindowExW.argtypes = [
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HWND,
        wintypes.HANDLE,
        wintypes.HINSTANCE,
        ctypes.c_void_p,
    ]
    CreateWindowExW.restype = wintypes.HWND

AGENT = """
'use strict';

const m = Process.getModuleByName('EDF5.exe');
if (!m) {
    send({ type: 'error', msg: 'EDF5.exe module not found' });
} else {
    const base = m.base;

    // PlayVoice: confirmed rcx=this, rdx=cueName
    const pvTarget = base.add(0x47C9D0);
    send({ type: 'info', msg: 'Hooking PlayVoice at ' + pvTarget });
    Interceptor.attach(pvTarget, {
        onEnter: function(args) {
            try {
                const name = args[1].readCString();
                if (name && name.length > 0)
                    send({ type: 'voice', fn: 'PlayVoice', name: name });
            } catch(e) {}
        }
    });

    // PlaySurroundVoice: corrected address (was 0x47BBA0, off by 0x1000)
    const psTarget = base.add(0x47CBA0);
    send({ type: 'info', msg: 'Hooking PlaySurroundVoice at ' + psTarget });
    Interceptor.attach(psTarget, {
        onEnter: function(args) {
            try {
                const name = args[1].readCString();
                if (name && name.length > 0)
                    send({ type: 'voice', fn: 'PlaySurroundVoice', name: name });
            } catch(e) {}
        }
    });

    // sub_1404777B0: common playback trigger — kept for reference, cue ID in args[2][0]
    // const pbTarget = base.add(0x4777B0);
    // Interceptor.attach(pbTarget, {
    //     onEnter: function(args) {
    //         try {
    //             const cueId = args[2].readInt();
    //             if (cueId !== -1)
    //                 send({ type: 'voice', fn: 'PlaybackTrigger', name: 'id=' + cueId });
    //         } catch(e) {}
    //     }
    // });

    send({ type: 'info', msg: 'Hooks installed — waiting for voice lines...' });
}
"""

LABELS = {
    'PlayVoice':         '[PV]',
    'PlaySurroundVoice': '[PS]',
}

COLORS = {
    'PlayVoice': PV_COLOR,
    'PlaySurroundVoice': PS_COLOR,
}


def load_subtitles(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError as exc:
        print(f"Failed to read {path}: {exc}", file=sys.stderr)
        sys.exit(1)

    subtitles: dict[str, str] = {}
    for line_number, line in enumerate(lines, start=1):
        if "=" not in line:
            print(
                f"Skipping malformed subtitle line {line_number} in {path.name}",
                file=sys.stderr,
            )
            continue
        cue, text = line.split("=", 1)
        subtitles[cue] = text
    return subtitles


def normalize_cue(name: str) -> str:
    if name.endswith("_E"):
        return name[:-2]
    return name


def load_cue_lengths(path: Path) -> dict[str, int]:
    if not path.exists():
        print(f"[WARN] {path.name} not found, using fixed subtitle timeout.", file=sys.stderr)
        return {}

    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError as exc:
        print(f"Failed to read {path}: {exc}", file=sys.stderr)
        return {}

    cue_lengths: dict[str, int] = {}
    for line_number, line in enumerate(lines, start=1):
        if "=" not in line:
            print(
                f"Skipping malformed cue length line {line_number} in {path.name}",
                file=sys.stderr,
            )
            continue

        cue, value = line.split("=", 1)
        try:
            duration_ms = int(value)
        except ValueError:
            print(
                f"Skipping non-integer cue length line {line_number} in {path.name}",
                file=sys.stderr,
            )
            continue

        if duration_ms < 0:
            print(
                f"Skipping negative cue length line {line_number} in {path.name}",
                file=sys.stderr,
            )
            continue

        cue_lengths[cue] = duration_ms

    return cue_lengths


def resolve_display_ms(raw_name: str, cue: str, cue_lengths: dict[str, int]) -> int:
    audio_ms = cue_lengths.get(raw_name)
    if audio_ms is None:
        audio_ms = cue_lengths.get(cue)
    if audio_ms is None:
        return FALLBACK_DISPLAY_MS
    return max(MIN_DISPLAY_MS, audio_ms + TAIL_PADDING_MS)


def get_game_pid() -> int | None:
    try:
        return frida.get_local_device().get_process("EDF5.exe").pid
    except frida.ProcessNotFoundError:
        return None


def get_window_rect(hwnd: int) -> tuple[int, int, int, int] | None:
    if not (IS_WINDOWS and hwnd):
        return None

    rect = wintypes.RECT()
    if not GetWindowRect(hwnd, ctypes.byref(rect)):
        return None

    left = rect.left
    top = rect.top
    right = rect.right
    bottom = rect.bottom
    if right <= left or bottom <= top:
        return None
    return left, top, right, bottom


def get_monitor_rect(hwnd: int) -> tuple[int, int, int, int] | None:
    if not (IS_WINDOWS and hwnd):
        return None

    monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST)
    if not monitor:
        return None

    monitor_info = MONITORINFO()
    monitor_info.cbSize = ctypes.sizeof(MONITORINFO)
    if not GetMonitorInfoW(monitor, ctypes.byref(monitor_info)):
        return None

    rect = monitor_info.rcMonitor
    if rect.right <= rect.left or rect.bottom <= rect.top:
        return None

    return rect.left, rect.top, rect.right, rect.bottom


def find_main_window(pid: int) -> int | None:
    if not IS_WINDOWS:
        return None

    matches: list[tuple[int, int]] = []
    enum_proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    @enum_proc
    def enum_windows_proc(hwnd, _lparam):
        if not IsWindowVisible(hwnd):
            return True

        window_pid = wintypes.DWORD()
        GetWindowThreadProcessId(hwnd, ctypes.byref(window_pid))
        if window_pid.value != pid:
            return True

        rect = get_window_rect(hwnd)
        if rect is None:
            return True

        left, top, right, bottom = rect
        area = (right - left) * (bottom - top)
        matches.append((area, int(hwnd)))
        return True

    if not EnumWindows(enum_windows_proc, 0):
        return None

    if not matches:
        return None

    matches.sort(reverse=True)
    return matches[0][1]


def colorref_from_hex(value: str) -> int:
    value = value.lstrip("#")
    red = int(value[0:2], 16)
    green = int(value[2:4], 16)
    blue = int(value[4:6], 16)
    return red | (green << 8) | (blue << 16)


_overlay_instances: dict[int, "SubtitleOverlay"] = {}


if IS_WINDOWS:
    @WNDPROC
    def overlay_wnd_proc(hwnd, msg, wparam, lparam):
        overlay = _overlay_instances.get(int(hwnd))
        if overlay is not None:
            return overlay.window_proc(hwnd, msg, wparam, lparam)
        return DefWindowProcW(hwnd, msg, wparam, lparam)
else:
    overlay_wnd_proc = None


class SubtitleOverlay:
    CLASS_NAME = "EDF5SubtitleOverlayWindow"
    _class_registered = False

    def __init__(self, game_hwnd: int | None = None) -> None:
        if not IS_WINDOWS:
            raise RuntimeError("Subtitle overlay only supports Windows.")

        self.game_hwnd = game_hwnd
        self.hwnd: int | None = None
        self.running = True
        self.window_width = 1
        self.window_height = WINDOW_HIDDEN_HEIGHT
        self.stack: list[tuple[str, str, float]] = []  # (text, fn, deadline)
        self.layout: list[tuple[str, int, wintypes.RECT]] = []
        self.target_left = 0
        self.target_top = 0
        self.target_right = GetSystemMetrics(SM_CXSCREEN)
        self.target_bottom = GetSystemMetrics(SM_CYSCREEN)
        self.next_topmost_refresh = 0.0
        self.bg_brush = CreateSolidBrush(colorref_from_hex(BG_COLOR))
        self.font = self.create_font()

        self.register_window_class()
        self.create_window()
        self.relayout()

    @classmethod
    def register_window_class(cls) -> None:
        if cls._class_registered:
            return

        wnd_class = WNDCLASSW()
        wnd_class.style = 0
        wnd_class.lpfnWndProc = overlay_wnd_proc
        wnd_class.cbClsExtra = 0
        wnd_class.cbWndExtra = 0
        wnd_class.hInstance = GetModuleHandleW(None)
        wnd_class.hIcon = 0
        wnd_class.hCursor = 0
        wnd_class.hbrBackground = 0
        wnd_class.lpszMenuName = None
        wnd_class.lpszClassName = cls.CLASS_NAME

        atom = RegisterClassW(ctypes.byref(wnd_class))
        error = ctypes.get_last_error()
        if not atom and error not in (0, 1410):
            raise OSError(f"RegisterClassW failed with {error}")
        cls._class_registered = True

    def create_font(self) -> int:
        desktop_dc = GetDC(0)
        dpi_y = GetDeviceCaps(desktop_dc, LOGPIXELSY) if desktop_dc else 96
        if desktop_dc:
            ReleaseDC(0, desktop_dc)
        pixel_height = -max(1, int(FONT_POINT_SIZE * dpi_y / 72))
        return CreateFontW(
            pixel_height,
            0,
            0,
            0,
            FONT_WEIGHT_BOLD,
            0,
            0,
            0,
            1,
            0,
            0,
            5,
            0,
            FONT_FACE,
        )

    def create_window(self) -> None:
        ex_style = WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE
        style = WS_POPUP
        hwnd = CreateWindowExW(
            ex_style,
            self.CLASS_NAME,
            "EDF5 Voice Hook",
            style,
            0,
            0,
            1,
            WINDOW_HIDDEN_HEIGHT,
            0,
            0,
            GetModuleHandleW(None),
            None,
        )
        if not hwnd:
            error = ctypes.get_last_error()
            raise OSError(f"CreateWindowExW failed with {error}")

        self.hwnd = int(hwnd)
        _overlay_instances[self.hwnd] = self

        alpha = max(0, min(255, int(WINDOW_ALPHA * 255)))
        if not SetLayeredWindowAttributes(self.hwnd, 0, alpha, LWA_ALPHA):
            error = ctypes.get_last_error()
            print(f"[WARN] SetLayeredWindowAttributes failed with {error}", file=sys.stderr)

    def update_target_bounds(self) -> None:
        rect = None
        if self.game_hwnd and IsWindow(self.game_hwnd):
            root_hwnd = GetAncestor(self.game_hwnd, GA_ROOT) or self.game_hwnd
            rect = get_monitor_rect(int(root_hwnd)) or get_window_rect(int(root_hwnd))

        if rect is None:
            rect = (
                0,
                0,
                GetSystemMetrics(SM_CXSCREEN),
                GetSystemMetrics(SM_CYSCREEN),
            )

        self.target_left, self.target_top, self.target_right, self.target_bottom = rect

    def current_width(self) -> int:
        target_width = self.target_right - self.target_left
        return min(1200, max(320, target_width - 80))

    def current_x(self, width: int) -> int:
        target_width = self.target_right - self.target_left
        return self.target_left + max(WINDOW_MARGIN_X, (target_width - width) // 2)

    def current_y(self, height: int) -> int:
        target_height = self.target_bottom - self.target_top
        return self.target_top + max(
            WINDOW_MARGIN_X,
            target_height - height - WINDOW_MARGIN_BOTTOM,
        )

    def measure_text_height(self, text: str, width: int) -> int:
        if not text:
            return 0

        rect = wintypes.RECT(0, 0, width, 0)
        hdc = GetDC(self.hwnd or 0)
        if not hdc:
            return FONT_POINT_SIZE + 8

        old_font = SelectObject(hdc, self.font)
        try:
            DrawTextW(
                hdc,
                text,
                -1,
                ctypes.byref(rect),
                DT_CENTER | DT_WORDBREAK | DT_NOPREFIX | DT_CALCRECT,
            )
        finally:
            SelectObject(hdc, old_font)
            ReleaseDC(self.hwnd or 0, hdc)

        return max(rect.bottom - rect.top, FONT_POINT_SIZE + 8)

    def relayout(self) -> None:
        self.update_target_bounds()
        width = self.current_width()
        wrap_width = max(100, width - WINDOW_PAD_X * 2)
        active_lines = [
            (text, colorref_from_hex(COLORS[fn]))
            for text, fn, _ in self.stack
            if text.strip()
        ]

        if not active_lines:
            self.layout = []
            self.window_width = width
            self.window_height = WINDOW_HIDDEN_HEIGHT
            ShowWindow(self.hwnd, SW_HIDE)
            return

        layout: list[tuple[str, int, wintypes.RECT]] = []
        current_y = WINDOW_PAD_Y
        for index, (text, color) in enumerate(active_lines):
            height = self.measure_text_height(text, wrap_width)
            rect = wintypes.RECT(
                WINDOW_PAD_X,
                current_y,
                width - WINDOW_PAD_X,
                current_y + height,
            )
            layout.append((text, color, rect))
            current_y += height
            if index != len(active_lines) - 1:
                current_y += TEXT_GAP_Y

        height = current_y + WINDOW_PAD_Y
        x = self.current_x(width)
        y = self.current_y(height)

        self.layout = layout
        self.window_width = width
        self.window_height = height

        SetWindowPos(
            self.hwnd,
            HWND_TOPMOST,
            x,
            y,
            width,
            height,
            SWP_NOACTIVATE | SWP_SHOWWINDOW,
        )
        ShowWindow(self.hwnd, SW_SHOWNOACTIVATE)
        InvalidateRect(self.hwnd, None, True)
        UpdateWindow(self.hwnd)

    def refresh_topmost(self) -> None:
        if self.layout:
            SetWindowPos(
                self.hwnd,
                HWND_TOPMOST,
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW,
            )

    def show(self, fn: str, text: str, display_ms: int) -> None:
        deadline = time.monotonic() + display_ms / 1000.0
        if len(self.stack) >= SUBTITLE_STACK_MAX:
            evict = min(range(len(self.stack)), key=lambda i: self.stack[i][2])
            self.stack.pop(evict)
        self.stack.append((text, fn, deadline))
        self.relayout()

    def tick(self) -> None:
        now = time.monotonic()
        before = len(self.stack)
        self.stack = [e for e in self.stack if e[2] > now]
        if len(self.stack) != before:
            self.relayout()
            return

        if now >= self.next_topmost_refresh:
            self.next_topmost_refresh = now + TOPMOST_REFRESH_MS / 1000.0
            if self.layout:
                self.relayout()
                self.refresh_topmost()

    def pump_messages(self) -> None:
        msg = MSG()
        while PeekMessageW(ctypes.byref(msg), 0, 0, 0, PM_REMOVE):
            if msg.message == WM_DESTROY or msg.message == 0x0012:
                self.running = False
                if msg.message == 0x0012:
                    break
            TranslateMessage(ctypes.byref(msg))
            DispatchMessageW(ctypes.byref(msg))

    def close(self) -> None:
        self.running = False
        if self.hwnd:
            _overlay_instances.pop(self.hwnd, None)
            DestroyWindow(self.hwnd)
            self.hwnd = None
        if self.font:
            DeleteObject(self.font)
            self.font = 0
        if self.bg_brush:
            DeleteObject(self.bg_brush)
            self.bg_brush = 0

    def paint(self) -> None:
        paint_struct = PAINTSTRUCT()
        hdc = BeginPaint(self.hwnd, ctypes.byref(paint_struct))
        if not hdc:
            return

        try:
            client_rect = wintypes.RECT(0, 0, self.window_width, self.window_height)
            FillRect(hdc, ctypes.byref(client_rect), self.bg_brush)
            old_font = SelectObject(hdc, self.font)
            SetBkMode(hdc, TRANSPARENT)
            try:
                for text, color, rect in self.layout:
                    rect_copy = wintypes.RECT(rect.left, rect.top, rect.right, rect.bottom)
                    SetTextColor(hdc, color)
                    DrawTextW(
                        hdc,
                        text,
                        -1,
                        ctypes.byref(rect_copy),
                        DT_CENTER | DT_WORDBREAK | DT_NOPREFIX | DT_NOCLIP,
                    )
            finally:
                SelectObject(hdc, old_font)
        finally:
            EndPaint(self.hwnd, ctypes.byref(paint_struct))

    def window_proc(self, hwnd, msg, wparam, lparam):
        if msg == WM_NCHITTEST:
            return HTTRANSPARENT
        if msg == WM_MOUSEACTIVATE:
            return MA_NOACTIVATE
        if msg == WM_ERASEBKGND:
            return 1
        if msg == WM_PAINT:
            self.paint()
            return 0
        if msg == WM_DESTROY:
            self.running = False
            PostQuitMessage(0)
            return 0
        return DefWindowProcW(hwnd, msg, wparam, lparam)


def on_message(message, _, subtitles, cue_lengths, ui_queue):
    if message['type'] == 'send':
        p = message['payload']
        if p['type'] == 'voice':
            raw_name = p['name']
            cue = normalize_cue(raw_name)
            text = subtitles.get(cue)

            if text:
                display_ms = resolve_display_ms(raw_name, cue, cue_lengths)
                print(
                    f"{LABELS.get(p['fn'], '[??]')} {raw_name} -> {cue}"
                    f" [{display_ms}ms] :: {text}"
                )
                ui_queue.put((p['fn'], text, display_ms))
            else:
                print(
                    f"{LABELS.get(p['fn'], '[??]')} {raw_name} -> {cue} :: <missing>",
                    file=sys.stderr,
                )
        elif p['type'] == 'info':
            print(f"[INFO] {p['msg']}")
        elif p['type'] == 'error':
            print(f"[ERR ] {p['msg']}", file=sys.stderr)
    elif message['type'] == 'error':
        print(f"[FRIDA] {message['stack']}", file=sys.stderr)


def main():
    if not IS_WINDOWS:
        print("voice_hook.py currently supports Windows only.", file=sys.stderr)
        sys.exit(1)

    subtitles = load_subtitles(SUBTITLE_PATH)
    cue_lengths = load_cue_lengths(CUE_LENGTH_PATH)
    game_pid = get_game_pid()
    game_hwnd = find_main_window(game_pid) if game_pid else None

    if game_pid and game_hwnd:
        print(f"[INFO] EDF5 PID {game_pid}, detected HWND 0x{game_hwnd:X}.")
    elif game_pid:
        print(
            "[WARN] EDF5 process found, but the main window was not detected.",
            file=sys.stderr,
        )

    try:
        session = frida.attach("EDF5.exe")
    except frida.ProcessNotFoundError:
        print("EDF5.exe is not running. Launch the game first.", file=sys.stderr)
        sys.exit(1)
    except frida.PermissionDeniedError:
        print("Permission denied. Try running as Administrator.", file=sys.stderr)
        sys.exit(1)

    ui_queue: queue.SimpleQueue[tuple[str, str, int]] = queue.SimpleQueue()
    overlay = SubtitleOverlay(game_hwnd)

    script = session.create_script(AGENT)
    script.on(
        'message',
        lambda message, data: on_message(message, data, subtitles, cue_lengths, ui_queue),
    )
    script.load()

    print("Running. Press Ctrl+C to stop.")
    try:
        while overlay.running:
            overlay.pump_messages()
            while True:
                try:
                    fn, text, display_ms = ui_queue.get_nowait()
                    overlay.show(fn, text, display_ms)
                except queue.Empty:
                    break
            overlay.tick()
            time.sleep(0.01)
    except KeyboardInterrupt:
        print("Stopping...")
    finally:
        session.detach()
        overlay.close()


if __name__ == '__main__':
    main()
