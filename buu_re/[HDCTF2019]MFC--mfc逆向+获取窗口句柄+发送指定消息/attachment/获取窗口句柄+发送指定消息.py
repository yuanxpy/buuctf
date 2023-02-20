import win32gui
import win32con
import win32api
handle = win32gui.FindWindow(None,"Flag就在控件里")
if handle:
    win32api.SendMessage(handle,0x0464,0,0)
    print('success')
else:
    print('failure')