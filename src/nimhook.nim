import winim
import std/[strutils]

let NTDLL = LoadLibraryA("ntdll.dll")
proc funcAddr*(library: string, procname: string): PVOID =
    let lib = LoadLibraryA(library)
    let function = GetProcAddress(lib, procname)
    PVOID(function)
proc fromNTDLL*(procname: string): PVOID =
    let function = GetProcAddress(NTDLL, procname)
    PVOID(function)

type
  Hook* = object
    #OldProtection: var DWORD
    Original*: PVOID
    FunctionToHook*: PVOID
    HookFunction*: PVOID

proc newHook*(): Hook =
  result = Hook(
    #OldProtection: 0,
    Original: nil,
    FunctionToHook: nil,
    HookFunction: nil
  )

proc init*(hook: var Hook, toHook: proc | PVOID, hookFunc: proc | PVOID) =
    var original = addr hook.Original
    copyMem(original, addr toHook, 16)
    hook.FunctionToHook = toHook
    hook.HookFunction = hookFunc

proc enable*(hook: Hook): bool {.discardable.} =
    let fDest = hook.FunctionToHook
    let fSrc = hook.HookFunction
    echo("Hooking Function At Address " & repr(fDest))
    echo("Hook Function " & repr(fSrc))
    var patch: seq[byte]
    case defined(amd64):
    of true:
        patch = @[
            byte(0x49), byte(0xBA), byte(0x00), byte(0x00), byte(0x00), byte(0x00), byte(0x00), byte(0x00), 
            byte(0x00),byte(0x00),byte(0x41), byte(0xFF),byte(0xE2)                                       
        ]
        var to = cast[uint64](fSrc)
        copyMem(&patch[2], &to , sizeof(to))

    of false:
        patch = @[
            byte(0xB8), byte(0x00), byte(0x00), byte(0x00), byte(0x00),
            byte(0x00),byte(0x00),byte(0xFF), byte(0xE0)                                      # jmp eax
        ]
        var to = cast[uint32](fSrc)
        copyMem(&patch[2], &to , sizeof(to))
    echo(patch)
    var old: DWORD = 0.DWORD
    let okProt = VirtualProtect(fDest, sizeof(patch).SIZE_T , PAGE_EXECUTE_READWRITE, &old)
    if okProt == 1:
        copyMem(fDest, &patch[0], sizeof(patch))
        return true
    else:
        #echo("[-] Failed to Hook Procedure.")
        return false

proc disable*(hook: Hook) =
    #let oldProt = hook.OldProtection
    let original = hook.Original
    echo("soon.tm")

proc `$`*(addry: PVOID): string = "0x" & repr(addry).replace("0000","").toLower()
proc on*(hook: Hook): bool {.discardable.} = enable(hook)
proc off*(hook: Hook): bool = disable(hook)
proc `$`*(hook: Hook): string = $(hook.FunctionToHook) & " " & $(hook.HookFunction)

#[
    proc detourF() =
    echo("[*] Hook Function Called.")
    MessageBoxW(0,L"HOOKED",L"HOOKED",0)

let hook = newHook(
        funcAddr("user32.dll","MessageBoxA"),
        detourF
    )

let success = hook.on
echo(success)
type msgbox = proc (hWnd: HWND, lpText: LPCSTR, lpCaption: LPCSTR, uType: UINT): int32{.stdcall.}
MessageBoxA(0,"test","test",0)
discard cast[msgbox](hook.Original)(HWND(0),"h00ked","h00ked",0)
]#