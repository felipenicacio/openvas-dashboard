#!/usr/bin/env python3
"""
Utilitário para gerar hash Argon2id de senha.

Uso:
    python generate_hash.py

O hash gerado deve ser definido como APP_PASSWORD_HASH no arquivo .env.
Nunca armazene a senha em texto puro — apenas o hash.

Referência: OWASP Password Storage Cheat Sheet (Argon2id).
"""

import getpass
import sys


def main() -> None:
    try:
        from argon2 import PasswordHasher
        from argon2.exceptions import HashingError
    except ImportError:
        print("ERRO: argon2-cffi não instalado. Execute: pip install argon2-cffi", file=sys.stderr)
        sys.exit(1)

    print("=== Gerador de hash Argon2id — OpenVAS Dashboard ===")
    print()

    try:
        password = getpass.getpass("Digite a senha: ")
        if not password:
            print("ERRO: Senha não pode ser vazia.", file=sys.stderr)
            sys.exit(1)

        confirm = getpass.getpass("Confirme a senha: ")
        if password != confirm:
            print("ERRO: Senhas não conferem.", file=sys.stderr)
            sys.exit(1)

        if len(password) < 12:
            print("AVISO: Senha com menos de 12 caracteres — considere uma mais forte.", file=sys.stderr)

    except (KeyboardInterrupt, EOFError):
        print("\nCancelado.", file=sys.stderr)
        sys.exit(1)

    # Parâmetros alinhados com backend/app/security.py
    ph = PasswordHasher(
        time_cost=3,
        memory_cost=65536,   # 64 MB
        parallelism=4,
        hash_len=32,
        salt_len=16,
    )

    try:
        hashed = ph.hash(password)
    except HashingError as exc:
        print(f"ERRO ao gerar hash: {exc}", file=sys.stderr)
        sys.exit(1)

    print()
    print("Hash gerado (adicione ao seu .env):")
    print()
    print(f"APP_PASSWORD_HASH={hashed}")
    print()
    print("IMPORTANTE: Nunca commite o arquivo .env no repositório.")


if __name__ == "__main__":
    main()
