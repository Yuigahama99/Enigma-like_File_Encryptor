.Const
GENERIC_READ  equ 080000000h
GENERIC_WRITE equ 40000000h
OPEN_EXISTING equ 3
FILE_ATTRIBUTE_NORMAL equ 080h
INVALID_FILE_HANDLE equ -1

.Data
hInst	     dq	 0
hin          dq  0
hout         dq  0
hfile        dq  0
bin			 dd  0
bout         dd  0
;------------------
htitle       db 'FILE READER',0dh,0ah
hprompt      db 'Enter file name: '
badfile      db "Can't find that file, sorry...",0Dh,0Ah
strbuff      db 128 dup 0
outline      db 80 dup 0
             db 0dh,0Ah
.Code 
start:
	invoke GetModuleHandleA, 0
	mov [hInst], Rax
    arg -10                ;STD_INPUT_HANDLE
    invoke GetStdHandle    ;handle returned in eax
    mov [hin],eax          ;store
    arg -11                ;STD_OUTPUT_HANDLE
    invoke GetStdHandle    ;handle returned in eax
    mov [hout],eax         ;store
	Invoke Main
	Invoke ExitProcess,0

    ;=========================================
    ; make displayable hex word in ebx from al
hexch:
    push eax
    and  eax,0Fh			; get nibble
    add  al,30h				; assume its numeric
    cmp  al,39h				; check
    jle  >
    add  al,7				; if not make it uppercase alpha
:   mov  bh,al				; store in bh (note endian switch when we store)
    pop  eax
    shr  al,4				; move top nibble to bottom
    add  al,30h				; assume its numeric
    cmp  al,39h				; check
    jle  >
    add  al,7				; if not make it uppercase alpha
:   mov bl,al				; store in bl 
    ret

getfilename FRAME
    uses eax, ebx,edi
    invoke WriteFile,[hout],addr htitle,13,addr bout,0 
    invoke GetCommandLineA
:   mov  bl,[eax]			; get next character from path\executable
    test bl,bl				; is this zero?
    jz   >nofile			; end of command line so no arguments
    inc  eax
    cmp  bl,020h			; is it a space?
    je   >getfile 			; yes means there's a command line argument coming
    jmp  <
getfile:
    mov  edi, addr strbuff
:   inc  eax				; next character...
    mov  bl,[eax]			; move next filename char to strbuff
    mov  [edi],bl			; store character into strbuff
    cmp  bl,00h				; have we reached end of filename?
    je   >gotname
    inc edi
	jmp <
nofile:
    invoke WriteFile,[hout],addr hprompt,17,addr bout,0 
    invoke ReadFile,[hin], addr strbuff,128,addr bin,0
    mov eax,[bin]
    sub eax,2
    mov b[strbuff+eax],00h
gotname:
   ret
EndF

Main Frame
    invoke getfilename
    ;-----------------------------------
    ; open file
    invoke  CreateFileA,ADDR strbuff,GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0           
    mov     [hfile], eax
    cmp     eax,INVALID_FILE_HANDLE
    je      >badfilename
    invoke  GetFileSize,[hfile],0
    mov     r15, eax
    xor     r14,r14
loopread:
	;------------------------------------
	; space fill the output line
    mov d[outline],20202020h			; space fill first doubleword
    mov ecx,19							; set repeat count to 19
    mov esi,addr outline				; source starts at first double word
    mov edi,addr outline + 4			; destination starts at second doubleword
    rep movsd 							; clear the complete line
    mov  edi,addr outline				; position in outline
    ;-------------------------------------
    ; write address in hex
    mov   ecx,4							; prepare for 4 byte (32 bit) addressing
    mov   eax,r14						; get current file position	
    bswap eax							; swap to put out most significant byte first
:   call  hexch							; get displayable hex representation of al
    mov   [edi],bx						; write out 
    add   edi,2							; update output line pointer 
	shr   eax,8							; position at next 
    loop  <								; and go back to do it
    add edi,2							; position ready for file data
    ;-------------------------------------     
    ; file read next chunk 
    xor rax,rax
    mov [strbuff],rax
    mov [strbuff+8],rax
    invoke ReadFile,[hfile],addr strbuff,16,addr bin,0
    ;--------------------------------------
    ; display ascii form
    xor  ecx,ecx
alpha:
    mov  al,[strbuff+ecx]				; get next character
    cmp  al,20h							; 
    jge  >								; below the lowest printable character?
    mov  al,02Eh						; yes - make it a period 
:   cmp  al,7Eh							; 
    jle  >								; above the highest printable character?
    mov  al,02Eh						; yes - make it a period 
:   mov  [edi],al						; store in print line
    inc  edi
    inc  ecx
    cmp  ecx,16							; repeat for 16 byte block
    jl  alpha
    add  edi,2							; position for hex
    ;--------------------------------------
    ; display hex form
    xor  ecx,ecx
hexa:
    mov  al,[strbuff+ecx]				; get next character
    call hexch							;
    mov  [edi],bx						; write out 
    add  edi,2    
    inc  ecx
    cmp  ecx,16							; repeat for 16 byte block
    jl  hexa
    ;--------------------------------------
    ; end of setup, write line
    invoke  WriteFile,[hout],addr outline,82,addr bout,0 
    ;--------------------------------------
	; increase position in file, decrease bytes to write, are we finished?
    add     r14,16
    sub     r15,16
    jg      loopread
    ;-----------------------------------------
    ; tidy up
    invoke CloseHandle,[hfile]
    invoke CloseHandle,[hin]
    invoke CloseHandle,[hout]
    ret
    ;--------------------------------------
    ; CreateFile fails
badfilename:
    invoke WriteFile,[hout],addr badfile,32,addr bout,0 
    ret
EndF
