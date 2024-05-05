# Replace -sfm_resolution with -sfm_width and -sfm_height
Source Filmmaker uses the command line argument `-sfm_resolution` to set the resolution of the rendered video.

This argument is hard-coded to use a height choice of `720`, `1080`, or `2160` without width.

This patch changes the argument to `-sfm_width` and `-sfm_height` to allow for custom resolutions.

## Original Assembly Code
The original assembly code in `ifm.dll` for the `-sfm_resolution` argument is as follows:

```x86asm
...
InitializeCIFMTool:
...
CommandLineResolution:
0x102cb8d5  e8 16 b4 6c 00                                  CALL FUN_102c8cf0
0x102cb8da  8b d8                                           MOV EBX, EAX
0x102cb8dc  8b 3b                                           MOV EDI, dword ptr [EBX]
0x102cb8de  8d 8e bc fd ff ff                               LEA ECX, dword ptr [ESI + 0xfffffdbc]
0x102cb8e4  e8 67 3b 73 00                                  CALL 0x102ff450
0x102cb8e9  8b 97 e4 01 00 00                               MOV EDX, dword ptr [EDI + 0x1e4]
0x102cb8ef  50                                              PUSH EAX
0x102cb8f0  8b cb                                           MOV ECX, EBX
0x102cb8f2  ff d2                                           CALL EDX
0x102cb8f4  8b 1d 7c e4 a7 10                               MOV EBX, dword ptr [0x10a7e47c]     ; TIER0.DLL::CommandLine
0x102cb8fa  8b fe                                           MOV EDI, ESI
0x102cb8fc  8b 0d 8c c7 f4 10                               MOV ECX, dword ptr [0x10f4c78c]
0x102cb902  8b 01                                           MOV EAX, dword ptr [ECX]
0x102cb904  8b 90 88 00 00 00                               MOV EDX, dword ptr [EAX + 0x88]
0x102cb90a  ff d2                                           CALL EDX
0x102cb90c  89 87 d8 01 00 00                               MOV dword ptr [EDI + 0x1d8], EAX    ; Set a pointer in CIFMTool
0x102cb912  ff d3                                           CALL EBX                            ; TIER0.DLL::CommandLine
0x102cb914  8b 10                                           MOV EDX, dword ptr [EAX]
; Begin patch area
0x102cb916  68 d0 02 00 00                                  PUSH 0x2d0                          ; Default height (720)
0x102cb91b  8b c8                                           MOV ECX, EAX
0x102cb91d  8b 42 1c                                        MOV EAX, dword ptr [EDX + 0x1c]
0x102cb920  68 84 90 ae 10                                  PUSH 0x10ae9084                     ; "-sfm_resolution"
0x102cb925  ff d0                                           CALL EAX                            ; CommandLine()->FindParm("-sfm_resolution")
0x102cb927  3d 70 08 00 00                                  CMP EAX, 0x870                      ; Maximum height (2160)
0x102cb92c  7c 16                                           JL SetResolution1080                     
0x102cb92e  c7 87 e8 01 00 00 70 08 00 00                   MOV dword ptr [EDI + 0x1e8], 0x870  ; Set height to 2160
0x102cb938  c7 87 e4 01 00 00 00 0f 00 00                   MOV dword ptr [EDI + 0x1e4], 0xf00  ; Set width to 3840
0x102cb942  eb 31                                           JMP AfterResolutionSet
SetResolution1080:
0x102cb944  3d 38 04 00 00                                  CMP EAX, 0x438                      ; Maximum height (1080)
0x102cb949  7c 16                                           JL SetResolution720
0x102cb94b  c7 87 e8 01 00 00 38 04 00 00                   MOV dword ptr [EDI + 0x1e8], 0x438  ; Set height to 1080
0x102cb955  c7 87 e4 01 00 00 80 07 00 00                   MOV dword ptr [EDI + 0x1e4], 0x780  ; Set width to 1920
0x102cb95f  eb 14                                           JMP AfterResolutionSet
SetResolution720:
0x102cb961  c7 87 e8 01 00 00 d0 02 00 00                   MOV dword ptr [EDI + 0x1e8], 0x2d0  ; Set height to 720
0x102cb96b  c7 87 e4 01 00 00 00 05 00 00                   MOV dword ptr [EDI + 0x1e4], 0x500  ; Set width to 1280
; End patch area
AfterResolutionSet:
0x102cb975  66 0f 6e 87 e4 01 00 00                         MOVD XMM0,dword ptr [EDI + 0x1e4]
...
0x10a7e47c  c6 47 e7 00                                     addr TIER0.DLL::CommandLine         ; Import CommandLine from tier0.dll
...
0x10a957d8  43 6f 6d 69 63 20 49 6e 73 70 65 63 74 6f 72 00 "Comic Inspector"                   ; Unused string
...
0x10ae9084  2d 73 66 6d 5f 72 65 73 6f 6c 75 74 69 6f 6e 00 "-sfm_resolution"
...
```

[Ghidra](https://ghidra-sre.org/) was used to disassemble `ifm.dll` and a `0x10000000` base address was used to match its disassembly.

## Patched Assembly Code
The patched assembly code in `ifm.dll` for the `-sfm_width` and `-sfm_height` arguments is as follows:

```x86asm
...
InitializeCIFMTool:
...
CommandLineResolution:
...
; Begin patch area
0x102cb916  68 48 05 00 00                                  PUSH 0x500                          ; Default width (1280)
0x102cb91b  8b c8                                           MOV ECX, EAX
0x102cb91d  8b 42 1c                                        MOV EAX, dword ptr [EDX + 0x1c]
0x102cb920  68 d8 57 a9 10                                  PUSH 0x10a957d8                     ; "-sfm_width"
0x102cb925  ff d0                                           CALL EAX                            ; CommandLine()->FindParm("-sfm_width")
0x102cb927  89 87 e4 01 00 00                               MOV dword ptr [EDI + 0x1e4], EAX    ; Set width
0x102cb92c  ff d3                                           CALL EBX                            ; TIER0.DLL::CommandLine
0x102cb92e  8b 10                                           MOV EDX, dword ptr [EAX]
0x102cb930  68 48 05 00 00                                  PUSH 0x2d0                          ; Default height (720)
0x102cb935  8b c8                                           MOV ECX, EAX
0x102cb937  8b 42 1c                                        MOV EAX, dword ptr [EDX + 0x1c]
0x102cb93a  68 84 90 ae 10                                  PUSH 0x10ae9084                     ; "-sfm_height"
0x102cb93f  ff d0                                           CALL EAX                            ; CommandLine()->FindParm("-sfm_height")
0x102cb941  89 87 e8 01 00 00                               MOV dword ptr [EDI + 0x1e8], EAX    ; Set height
0x102cb947  66 90                                           NOP                                 ; Padding
0x102cb949  66 90                                           NOP                                 ; Padding
0x102cb94b  66 90                                           NOP                                 ; Padding
0x102cb94d  66 90                                           NOP                                 ; Padding
0x102cb94f  66 90                                           NOP                                 ; Padding
0x102cb951  66 90                                           NOP                                 ; Padding
0x102cb953  66 90                                           NOP                                 ; Padding
0x102cb955  66 90                                           NOP                                 ; Padding
0x102cb957  66 90                                           NOP                                 ; Padding
0x102cb959  66 90                                           NOP                                 ; Padding
0x102cb95b  66 90                                           NOP                                 ; Padding
0x102cb95d  66 90                                           NOP                                 ; Padding
0x102cb95f  66 90                                           NOP                                 ; Padding
0x102cb961  66 90                                           NOP                                 ; Padding
0x102cb963  66 90                                           NOP                                 ; Padding
0x102cb965  66 90                                           NOP                                 ; Padding
0x102cb967  66 90                                           NOP                                 ; Padding
0x102cb969  66 90                                           NOP                                 ; Padding
0x102cb96b  66 90                                           NOP                                 ; Padding
0x102cb96d  66 90                                           NOP                                 ; Padding
0x102cb96f  66 90                                           NOP                                 ; Padding
0x102cb971  66 90                                           NOP                                 ; Padding
0x102cb973  66 90                                           NOP                                 ; Padding
; End patch area
...
0x10a957d8  2d 73 66 6d 5F 77 69 64 74 68 00 00 00 00 00 00 "-sfm_width"                        ; New width argument
...
0x10ae9084  2d 73 66 6d 5f 68 65 69 67 68 74 00 00 00 00 00 "-sfm_height"                       ; Replace "-sfm_resolution"
...
```

```hex
68 48 05 00 00 8b c8 8b 42 1c 68 d8 57 a9 10 ff d0 89 87 e4 01 00 00 ff d3 8b 10 68 48 05 00 00 8b c8 8b 42 1c 68 84 90 ae 10 ff d0 89 87 e8 01 00 00 66 90 66 90 66 90 66 90 66 90 66 90 66 90 66 90 66 90 66 90 66 90 66 90 66 90 66 90 66 90 66 90 66 90 66 90 66 90 66 90 66 90 66 90 66 90
```
