.Const
GENERIC_READ          equ 080000000h
GENERIC_WRITE         equ 40000000h
CREATE_ALWAYS         equ 2
OPEN_EXISTING         equ 3
FILE_ATTRIBUTE_NORMAL equ 080h
INVALID_FILE_HANDLE   equ -1

.Data
;============================================================
; handle declearance
;============================================================
hInst   dq 0
bin     dd 0        ; console input
bout    dd 0        ; console output
hin     dq 0        ; handle for console input
hout    dq 0        ; handle for console output
hconfig dq 0        ; handle for configuration file
hfin    dq 0        ; handle for input file
hfout   dq 0        ; handle for output file

;============================================================
; working storage
;============================================================
charin  db 32 dup 0 ; input buffer
strbuff db 64 dup 0 ; filename buffer
m24     db 24       ; slot length
ciph    dd 0        ; cipher byte construct buffer

;============================================================
; messages
;============================================================
welcome  db 0Dh, 0Ah
		 db "Enigma-like file encryptor", 0Dh, 0Ah
		 db "  0...Exit", 0Dh, 0Ah
		 db "  1...Configure", 0Dh, 0Ah
		 db "  2...Cipher", 0Dh, 0Ah
		 db "> "
wlen     dd $-welcome
message1 db 0Ah, 0Dh, "Enter rotor for slot x: "
message2 db "Enter start character slot x: "
message3 db 0Ah, 0Dh, "Enter two characters for plug x: "
message4 db "Enter input  filename: "
message5 db "Enter output filename: "
message6 db "Configuration State  x-x x-x x-x xxxxxxxxxxxxxxxx ",0Dh,0Ah
confile  db "enigmatic.cfg", 0
badfile  db "Probelm with the file, sorry...", 0Dh, 0Ah
noconfig db "Cannot open the config file....", 0Dh, 0Ah

;============================================================
; menu jump table
;============================================================
jumptb dq addr exit
	   dq addr config
	   dq addr cipher

;============================================================
; configuration data
;============================================================
configdata db "Enigmatic Configuration"
;---------------------------------------------------
; rotor structure (rotor provides key stream)
rotor struct
	hex   dq
	notch db	
EndS
rotor1 rotor <01F46C8037B9AD25Eh, 0Fh>
rotor2 rotor <0EFA87B439D5216C0h, 03h>
rotor3 rotor <00F732D168C4BA59Eh, 0Dh>
rotor4 rotor <0F0E8143CA2695B9Dh, 00h>
rotor5 rotor <0AB8736E1F0C295D4h, 03h>
;---------------------------------------------------
; slot structure (rotor placed in slot)
slot struct
	rotty    rotor
	rotno    db
	rotstart db
EndS
slots slot 3 dup <>
;---------------------------------------------------
; plugs declearance (used to exchange char)
xplugs db 00h, 01h, 02h, 03h, 04h, 05h, 06h, 07h, 08h, 09h, 0Ah, 0Bh, 0Ch, 0Dh, 0Eh, 0Fh
;============================================================
; end of configuration data
;============================================================
configlen dd $-configdata

.Code
start:
	Invoke GetModuleHandleA, 0
	Mov    [hInst], Rax
	Invoke Main
exit:
	invoke CloseHandle, [hin]
	invoke CloseHandle, [hout]
	invoke CloseHandle, [hInst]
	Invoke ExitProcess, 0


;============================================================
; callable routine convert ASCII to hex 
;============================================================
hexConvert:
	sub al, 030h ; convert the ASCII character to binary
	cmp al, 09h  ; check if character is number
	jle >        ; is number, jump to hexout
	sub al, 7    ; adjuest for uppercase character
	cmp al, 0Fh  ; check is character is uppercase
	jle >        ; is uppercase, jump to hexout
	sub al, 020h ; is lowercase, transfer to uppercase
:	ret


;============================================================
; callable routine find nibble's position in rotor 
;============================================================
findpos:
	uses rbx, rdx
	xor rcx, rcx   ; clear rcx, start with position 0 
	mov rdx, [edi] ; load rotor's key stream to rdx
:	rol rdx, 4     ; rotate top nibble to lower 
	mov bl, dl      
	and bl, 0Fh    ; mask out the lowesr nibble 
	cmp bl, al     ; check if is the nibble requested
	je  >
	inc ecx        ; move to next position
	jmp <          ; loop back
:   ret
	EndU


;============================================================
; callable routine display running configuration 
;============================================================
displayconfig:
	uses eax, ecx, edi
	mov edi, addr message6
	mov al, [slots.rotno]       ; load slot1's rotor number
	mov [edi+21], al
	mov al, [slots.rotstart]    ; load slot1's start character
	mov [edi+23], al
	mov al, [slots.rotno+24]    ; load slot2's rotor number
	mov [edi+25], al
	mov al, [slots.rotstart+24] ; load slot2's start character
	mov [edi+27], al
	mov al, [slots.rotno+48]    ; load slot3's rotor number
	mov [edi+29], al
	mov al, [slots.rotstart+48] ; load slot3's start character
	mov [edi+31], al
	;---------------------------------------------------
	; load plug configuration to message6
	add edi, 33
	xor ecx, ecx
plugconfig:
	mov al, [xplugs+ecx]
	add al, 30h
	cmp al, 39h
	jle >
	add eax, 7
:	mov [edi+ecx], al
	inc ecx
	cmp ecx, 16
	jne plugconfig
	;---------------------------------------------------
	; display running configuration
	invoke WriteFile, [hout], addr message6, 52, addr bout, 0
	ret
	EndU


;============================================================
;  LoadPlug: load connection of the plug
;============================================================
LoadPlug Frame pplug
	uses rax, rbx
	;---------------------------------------------------
	; display message
	mov    eax, [pplug]  ; load plug number into eax
	add    eax, 030h     ; make plug number displayable
	lea    ebx, addr message3 ; load address of message3
	mov    b[ebx+32], al  ; replace x with plug number
	invoke WriteFile, [hout], addr message3, 35, addr bout, 0
	invoke ReadFile, [hin], addr charin, 4, addr bin, 0
	;---------------------------------------------------
	; establish connection
	mov  al, [charin]     ; load first byte into al
	and  rax, 0FFh        ; clear other parts of rax, leave al
	call hexConvert       ; convert first byte to hex
	mov  ebx, eax         ; store first byte's hex in ebx
	mov  al, [charin+1]   ; load second byte into al
	call hexConvert       ; convert second byte to hex
	mov  [xplugs+eax], bl ; connect al to bl
	mov  [xplugs+ebx], al ; connect bl to al
	Ret
EndF


;============================================================
;  LoadSlot: load slot setting
;============================================================
LoadSlot Frame pslotno
	uses rax, rbx, rcx, rdx, rdi
	;---------------------------------------------------
	; display message
	lea    edx, addr message1
	mov    ecx, [pslotno]
	add    ecx, 030h     ; convert pslotno to displayable
	mov    b[edx+23], cl ; replace the slot number x with pslotno
	invoke WriteFile, [hout], addr message1, 26, addr bout, 0
	invoke ReadFile, [hin], addr charin, 3, addr bin, 0
	;---------------------------------------------------
	; calculate the offset of the slot
	xor edx, edx        ; clear edx
	mov eax, [pslotno]  ; load pslotno into eax
	dec eax             ; convert to index by decrement
	mul b[m24]          ; calculate slot offset
	mov edi, addr slots ; load slots address into edi
	add edi, eax        ; calculate the slot's address
	;---------------------------------------------------
	; get rotor for the slot
	xor eax, eax           ; clear eax
	mov al, b[charin]      ; load rotor number into al
	sub al, 031h           ; convert ASCII to binary
	shl eax, 4             ; calculate the offset of the rotor 
	mov rbx, [rotor1+eax]  ; load requested rotor's address into rbx
	mov [edi], rbx         ; store key stream into the slot
	mov cl, [rotor1+eax+8] ; load notch into cl
	mov [edi+8], cl        ; store notch into the slot
	mov cl, [charin]       ; load rotor number into cl
	mov [edi+10h], cl      ; store rotor number into the slot
	;---------------------------------------------------
	; get start character for the slot
	lea    edx, addr message2
	mov    b[edx+27], 030h
	mov    eax, [pslotno]
	add    b[edx+27], al
	invoke WriteFile, [hout], addr message2, 30, addr bout, 0
	invoke ReadFile, [hin], addr charin, 3, addr bin, 0
	mov    al, [charin] 
	mov    [edi+011h], al ; store the start character
	call   hexConvert
:   mov    rbx, [edi]     ; load current slot's rotor into rbx
	rol    rbx, 4         ; rotate upper part to lower
	and    rbx, 0Fh       ; mask out the upper part
	cmp    al, bl         ; check if upper part equal to start character
	je     >              ; equal, quit
	rol    q[edi], 4      ; no equal, rotate the rotor
	jmp    <              ; loop again
:	Ret
EndF


;============================================================
;  Enigmate: main ciphering process
;============================================================
Enigmate Frame pnibble
	uses eax, ebx, ecx
	mov  ecx, [pnibble] ; load incomming nibble to ecx
	and  ecx, 0Fh       ; clear all other parts of ecx
	xor  eax, eax       ; clear eax
	;---------------------------------------------------
	; use plug to substitute the incomming nibble
	mov al, [xplugs+ecx]
	;---------------------------------------------------
	; run through all three slots' rotor
	invoke SlotFwd, 1, eax
	invoke SlotFwd, 2, eax
	invoke SlotFwd, 3, eax
	;---------------------------------------------------
	; symmetrical reflection
	not al      ; subsititute 0 for F, 1 for E, 2 for D...
	and al, 0Fh ; clear upper nibble in al
	;---------------------------------------------------
	; run back through all three slots' rotor
	invoke SlotBack, 3, eax
	invoke SlotBack, 2, eax
	invoke SlotBack, 1, eax
	;---------------------------------------------------
	; use plug to substitute the incomming nibble
	mov ecx, eax
	mov al, [xplugs+ecx]
	;---------------------------------------------------
	; store cipher nibble
	mov bl, [ciph] ; load the existing ciph nibble to bl
	shl bl, 4      ; move the nibble to the upper part
	or  bl, al     ; move in the lower nibble
	mov [ciph], bl ; store in ciph
	;---------------------------------------------------
	; rotate rotor in slot 1
	mov rax, [slots]            ; get the rotor in slot
	rol rax, 4                  ; rotate the rotor
	mov [slots], rax            ; store back to slot
	rol rax, 4                  ; rotate upper nibble to lower 
	and rax, 0Fh                ; mask out the lower nibble
	cmp al, [slots.rotty.notch] ; check if is notch
	jne >
	;---------------------------------------------------
	; rotate rotor in slot 2
	mov rax, [slots+24]            ; get the rotor in slot
	rol rax, 4                     ; rotate the rotor
	mov [slots+24], rax            ; store back to slot
	rol rax, 4                     ; rotate upper nibble to lower 
	and rax, 0Fh                   ; mask out the lower nibble
	cmp al, [slots.rotty.notch+24] ; check if is notch
	jne >
	;---------------------------------------------------
	; rotate rotor in slot 3
	mov rax, [slots+48]            ; get the rotor in slot
	rol rax, 4                     ; rotate the rotor
	mov [slots+48], rax            ; store back to slot
:	Ret
EndF
	

;============================================================
; SlotFwd: forward to slots' rotor to transpose nibble
;============================================================
SlotFwd Frame pslotno, pnibble
	uses ebx, ecx, edx, edi
	;---------------------------------------------------
	; access requested slot
	xor edx, edx
	mov eax, [pslotno]  ; load slot number to eax
	dec eax             ; convert slot number to range 0~2     
	mul b[m24]          ; calculate the slot offset
	mov edi, addr slots ; load slots address to edi
	mov rbx, [edi+eax]  ; access requested slot key stream
	;---------------------------------------------------
	; convert to nibble offset
	mov ecx, [pnibble]
	shl ecx, 2
	;---------------------------------------------------
	; find the subsititution nibble from key stream
	rol rbx, cl  ; rotate to the requested nibble
	rol rbx, 4   ; rotate the upper nibble to lower
	mov rax, rbx ; store the rotor into rax
	and rax, 0Fh ; mask out the other parts, leave nibble
	ret
EndF


;============================================================
; SlotBack: backward to slots' rotor to transpose nibble
;============================================================
SlotBack Frame pslotno, pnibble
	uses ecx, edi
	;---------------------------------------------------
	; access requested slot
	xor edx, edx
	mov eax, [pslotno]  ; load slot number
	dec eax             ; convert to data range 0~2
	mul b[m24]          ;
	mov edi, addr slots ; calculate the slot offset
	add edi, eax        ; get the address of the slot's key stream
	;---------------------------------------------------
	; locate the nibble
	mov eax, [pnibble] ; load requested nibble to al
	call findpos       ; find position in key stream
	mov al, cl         ; store the result in al
	ret
EndF


Main Frame
	;============================================================
	; get console handles
	;============================================================
	arg    -10         ; -10: STD_INPUT_HANDLE
	invoke GetStdHandle
	mov    [hin], eax  ; stored in hin
	arg    -11         ; -11: STD_OUTPUT_HANDLE
	invoke GetStdHandle
	mov    [hout], eax ; stored in hout
	
	;============================================================
	; display welcome message
	;============================================================
menu:
	invoke WriteFile, [hout], addr welcome, [wlen], addr bout, 0
	invoke ReadFile, [hin], addr charin, 3, addr bin, 0
	xor    eax, eax
	mov    al, [charin]
	sub    eax, 30h ; convert charin to binary
	shl    eax, 3   ; convert binary to jumptable offset
	call   [jumptb+eax]
	jmp    <menu    ; loop back to menu display
	
	;============================================================
	; jumptable: configuration
	;============================================================
config:
	;---------------------------------------------------
	; setup slots with rotor and start character
	invoke LoadSlot, 1
	invoke LoadSlot, 2
	invoke LoadSlot, 3
	;---------------------------------------------------
	; setup plugboard
	invoke LoadPlug, 1
	invoke LoadPlug, 2
	;---------------------------------------------------
	; store configuration data
	invoke CreateFileA, addr confile, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
	mov    [hconfig], eax
	cmp    eax, INVALID_FILE_HANDLE
	je     >badfilename
	invoke WriteFile, [hconfig], addr configdata, [configlen], addr bout, 0
	invoke CloseHandle, [hconfig]
	ret
	
	;============================================================
	; jumptable: cipher
	;============================================================
cipher:
	;---------------------------------------------------
	; recover from config file
	invoke CreateFileA, addr confile, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
	mov    [hconfig], eax
	cmp    eax, INVALID_FILE_HANDLE
	je     >badconfig
	invoke ReadFile, [hconfig], addr configdata, [configlen], addr bin, 0
	invoke CloseHandle, [hconfig]
	invoke displayconfig
	;---------------------------------------------------
	; get input file name and open it
	invoke WriteFile, [hout], addr message4, 23, addr bout, 0
	invoke ReadFile, [hin], addr strbuff, 60, addr bin, 0
	mov    eax, [bin]
	sub    eax, 2
	mov    b[strbuff+eax], 00h
	invoke CreateFileA, addr strbuff, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
	mov    [hfin], eax
	cmp    eax, INVALID_FILE_HANDLE
	je     >badfilename
	;---------------------------------------------------
	; get output file name and open it
	invoke WriteFile, [hout], addr message5, 23, addr bout, 0
	invoke ReadFile, [hin], addr strbuff, 60, addr bin, 0
	mov    eax, [bin]
	sub    eax, 2
	mov    b[strbuff+eax], 00h
	invoke CreateFileA, addr strbuff, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
	mov    [hfout], eax
	cmp    eax, INVALID_FILE_HANDLE
	je     >badfilename
	;---------------------------------------------------
	; get input file size
	invoke GetFileSize, [hfin], 0
	mov    r15, eax
cipherfile:
	;---------------------------------------------------
	; get the next character from input file
	invoke ReadFile, [hfin], addr charin, 1, addr bin, 0
	xor    eax, eax
	mov    [ciph], eax
	mov    al, [charin]
	shr    al , 4
	invoke Enigmate, eax
	mov    al, [charin]
	and    al, 0Fh
	invoke Enigmate, eax
	;---------------------------------------------------
	; store the ciphered byte to output file
	invoke WriteFile, [hfout], addr ciph, 1, addr bout, 0
	dec    r15
	jnz    cipherfile
	invoke CloseHandle, [hfin]
	invoke CloseHandle, [hfout]
	ret
	
	;============================================================
	; display error message
	;============================================================
badfilename:
	invoke WriteFile, [hout], addr badfile, 32, addr bout, 0
	ret
badconfig:
	invoke WriteFile, [hout], addr noconfig, 32, addr bout, 0
	ret	
EndF