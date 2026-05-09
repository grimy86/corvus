.686
.model flat, C
option casemap:none

EXTERN recoilJumpBackAddress : DWORD

.code

RecoilAssemblyHook PROC

    push eax
    push ecx
    push edx

    mov eax, 050F4F4h
    mov eax, [eax]              ; player*

    mov ecx, [eax + 374h]       ; weapon*
    mov edx, [ecx + 14h]        ; ammo*
    mov dword ptr [edx], 053Ah

    mov ecx, eax                ; player*
    add ecx, 0F8h               ; healthOffset
    mov dword ptr [ecx], 0539h

    add ecx, 4                  ; ammoOffset
    mov dword ptr [ecx], 0539h

    pop edx
    pop ecx
    pop eax

    mov word ptr [edi + 122h], 0
    movsx ecx, word ptr [edi + 122h]

    jmp recoilJumpBackAddress

RecoilAssemblyHook ENDP

END