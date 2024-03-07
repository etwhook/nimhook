
# 🪝 NimHook
Simple API **Hooking** / **Detouring** 🪝 Library Written In **Nim**.
 
## 📺 Usage
```nim
import nimhook, winim
type msgbox = proc (hWnd: HWND, lpText: LPCSTR, lpCaption: LPCSTR, uType: UINT): int32{.stdcall.}

var hook = newHook()
proc detour() =
    MessageBoxW(0,L"hooked",L"hooked",0)

hook.init(funcAddr("user32.dll","MessageBoxA") , detour)

MessageBoxA(0,"unhooked function","unhooked",0)
hook.enable()
MessageBoxA(0,"this will be hooked","this will be hooked",0)
hook.disable() # implementation soon
```
## 🛠️ Output
```
0x7ff8b54c9980
Hooking Function At Address 00007FF8B54C9980
Hook Function 00007FF6421B98A9
@[73, 186, 169, 152, 27, 66, 246, 127, 0, 0, 65, 255, 226] <= Patch Byte Sequence

```
## 📜 Todo
- Implement **hook.disable()** function.
- Fix **Original** Bytes Copying **Hooked** Function.
