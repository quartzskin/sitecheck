import ctypes
from ctypes import wintypes

from .png import encode_rgb

PW_RENDERFULLCONTENT = 2


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG), ("biHeight", wintypes.LONG),
                ("biPlanes", wintypes.WORD), ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG), ("biYPelsPerMeter", wintypes.LONG),
                ("biClrUsed", wintypes.DWORD), ("biClrImportant", wintypes.DWORD)]


def capture(tk_root, path):
    """Render a Tk window to a PNG with PrintWindow; needs a Windows desktop session."""
    user32, gdi32 = ctypes.windll.user32, ctypes.windll.gdi32
    hnd = wintypes.HANDLE
    user32.GetParent.restype, user32.GetParent.argtypes = hnd, [hnd]
    user32.GetDC.restype, user32.GetDC.argtypes = hnd, [hnd]
    user32.ReleaseDC.argtypes = [hnd, hnd]
    user32.PrintWindow.argtypes = [hnd, hnd, wintypes.UINT]
    user32.GetWindowRect.argtypes = [hnd, ctypes.POINTER(wintypes.RECT)]
    gdi32.CreateCompatibleDC.restype, gdi32.CreateCompatibleDC.argtypes = hnd, [hnd]
    gdi32.CreateCompatibleBitmap.restype, gdi32.CreateCompatibleBitmap.argtypes = hnd, [hnd, ctypes.c_int, ctypes.c_int]
    gdi32.SelectObject.restype, gdi32.SelectObject.argtypes = hnd, [hnd, hnd]
    gdi32.DeleteObject.argtypes = [hnd]
    gdi32.DeleteDC.argtypes = [hnd]
    gdi32.GetDIBits.argtypes = [hnd, hnd, wintypes.UINT, wintypes.UINT, ctypes.c_void_p, ctypes.c_void_p, wintypes.UINT]

    inner = tk_root.winfo_id()
    hwnd = user32.GetParent(inner) or inner
    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    w, h = rect.right - rect.left, rect.bottom - rect.top
    screen = user32.GetDC(None)
    mem = gdi32.CreateCompatibleDC(screen)
    bmp = gdi32.CreateCompatibleBitmap(screen, w, h)
    old = gdi32.SelectObject(mem, bmp)
    try:
        if not user32.PrintWindow(hwnd, mem, PW_RENDERFULLCONTENT):
            raise OSError("PrintWindow failed")
        info = BITMAPINFOHEADER(ctypes.sizeof(BITMAPINFOHEADER), w, -h, 1, 32, 0)
        buf = ctypes.create_string_buffer(w * h * 4)
        if not gdi32.GetDIBits(mem, bmp, 0, h, buf, ctypes.byref(info), 0):
            raise OSError("GetDIBits failed")
    finally:
        gdi32.SelectObject(mem, old)
        gdi32.DeleteObject(bmp)
        gdi32.DeleteDC(mem)
        user32.ReleaseDC(None, screen)
    bgra = buf.raw
    rgb = bytearray(w * h * 3)
    rgb[0::3], rgb[1::3], rgb[2::3] = bgra[2::4], bgra[1::4], bgra[0::4]
    with open(path, "wb") as fh:
        fh.write(encode_rgb(w, h, bytes(rgb)))
    return w, h
