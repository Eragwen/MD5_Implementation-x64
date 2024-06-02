section .data
    init_values: dd 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

    ; Table de constantes pour les transformations
    k_values: dd 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee
              dd 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501
              dd 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be
              dd 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821
              dd 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa
              dd 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8
              dd 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed
              dd 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a
              dd 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c
              dd 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70
              dd 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05
              dd 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665
              dd 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039
              dd 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1
              dd 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1
              dd 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391

    ; Table de décalages pour chaque ronde
    shift_values: db 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22
                  db 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20
                  db 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23
                  db 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21

section .bss
    buffer resb 64
    digest resb 16

section .text
global _start

_start:
    ; Initialisation des registres
    mov rsi, buffer
    mov rdi, digest
    call md5_init

    ; Exemple de message (padding manuel pour simplification)
    mov rsi, buffer
    mov qword [rsi], 0x61626380    ; "abc" suivi de padding 0x80
    mov qword [rsi + 8], 0
    mov qword [rsi + 16], 0
    mov qword [rsi + 24], 0
    mov qword [rsi + 32], 0
    mov qword [rsi + 40], 0
    mov qword [rsi + 48], 0
    mov qword [rsi + 56], 24 * 8   ; Longueur du message original en bits

    call md5_update

    ; Finalisation du hachage
    mov rsi, digest
    call md5_final

    ; Sortie du programme
    mov eax, 60         ; syscall: exit
    xor edi, edi        ; status: 0
    syscall

md5_init:
    ; Initialise les valeurs de hachage
    mov rax, init_values
    mov rcx, 4
.init_loop:
    mov edx, [rax]
    mov [rsi + (rcx - 1) * 4], edx
    add rax, 4
    loop .init_loop
    ret

md5_update:
    ; Sauvegarder les registres de travail
    push rbx
    push rbp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15

    mov rsi, buffer
    mov rdi, k_values
    mov rdx, shift_values

    ; Découpe le message en blocs de 512 bits (64 octets)
    mov rcx, 1
.update_loop:
    call md5_transform
    loop .update_loop

    ; Restaurer les registres de travail
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    pop rbx
    ret

md5_final:
    ; Combine les valeurs finales pour produire le hachage final
    mov rax, rsi
    mov rcx, 4
.final_loop:
    mov edx, [rax + (rcx - 1) * 4]
    mov [rdi + (rcx - 1) * 4], edx
    loop .final_loop
    ret

md5_transform:
    ; Sauvegarde les valeurs initiales
    mov eax, [digest + 0]
    mov ebx, [digest + 4]
    mov ecx, [digest + 8]
    mov edx, [digest + 12]

    ; Variables temporaires pour les transformations
    mov r8d, eax
    mov r9d, ebx
    mov r10d, ecx
    mov r11d, edx

    ; Ronde 1
    mov rsi, k_values
    mov rdi, shift_values
    mov rcx, 16  ; Nombre d'itérations par ronde
.round1:
    ; F(b, c, d) = (b & c) | (~b & d)
    mov r8d, ebx
    and r8d, ecx
    mov r9d, ebx
    not r9d
    and r9d, edx
    or r8d, r9d

    ; a = a + F(b, c, d) + X[k] + T[i]
    add eax, r8d
    add eax, [buffer + (rcx - 1) * 4]  ; X[k]
    add eax, [rsi + (rcx - 1) * 4]  ; T[i]

    ; a = a <<< s
    rol eax, byte [rdi + (rcx - 1)]

    ; a = b + a
    add eax, ebx

    ; Rotation des variables a, b, c, d
    xchg eax, edx
    xchg edx, ecx
    xchg ecx, ebx

    loop .round1

    ; Ronde 2
    mov rcx, 16
.round2:
    ; G(b, c, d) = (b & d) | (c & ~d)
    mov r8d, edx
    and r8d, ebx
    mov r9d, ecx
    not r9d
    and r9d, edx
    or r8d, r9d

    ; a = a + G(b, c, d) + X[k] + T[i]
    add eax, r8d
    ; Calcul explicite de (rcx * 5 + 1) % 16
    mov r8d, rcx
    lea r9d, [r8d * 5 + 1]
    and r9d, 15
    shl r9d, 2
    add eax, [buffer + r9d]  ; X[k]
    add eax, [rsi + 16 + rcx * 4]  ; T[i]

    ; a = a <<< s
    rol eax, byte [rdi + (16 + rcx - 1)]

    ; a = b + a
    add eax, ebx

    ; Rotation des variables a, b, c, d
    xchg eax, edx
    xchg edx, ecx
    xchg ecx, ebx

    loop .round2

    ; Ronde 3
    mov rcx, 16
.round3:
    ; H(b, c, d) = b ^ c ^ d
    mov r8d, ebx
    xor r8d, ecx
    xor r8d, edx

    ; a = a + H(b, c, d) + X[k] + T[i]
    add eax, r8d
    ; Calcul explicite de (rcx * 3 + 5) % 16
    mov r8d, rcx
    lea r9d, [r8d * 3 + 5]
    and r9d, 15
    shl r9d, 2
    add eax, [buffer + r9d]  ; X[k]
    add eax, [rsi + 32 + rcx * 4]  ; T[i]

    ; a = a <<< s
    rol eax, byte [rdi + (32 + rcx - 1)]

    ; a = b + a
    add eax, ebx

    ; Rotation des variables a, b, c, d
    xchg eax, edx
    xchg edx, ecx
    xchg ecx, ebx

    loop .round3

    ; Ronde 4
    mov rcx, 16
.round4:
    ; I(b, c, d) = c ^ (b | ~d)
    mov r8d, ecx
    not r9d
    or r9d, edx
    xor r8d, r9d

    ; a = a + I(b, c, d) + X[k] + T[i]
    add eax, r8d
    ; Calcul explicite de (rcx * 7) % 16
    mov r8d, rcx
    lea r9d, [r8d * 7]
    and r9d, 15
    shl r9d, 2
    add eax, [buffer + r9d]  ; X[k]
    add eax, [rsi + 48 + rcx * 4]  ; T[i]

    ; a = a <<< s
    rol eax, byte [rdi + (48 + rcx - 1)]

    ; a = b + a
    add eax, ebx

    ; Rotation des variables a, b, c, d
    xchg eax, edx
    xchg edx, ecx
    xchg ecx, ebx

    loop .round4

    ; Mise à jour des valeurs de hachage
    add [digest + 0], eax
    add [digest + 4], ebx
    add [digest + 8], ecx
    add [digest + 12], edx

    ret
