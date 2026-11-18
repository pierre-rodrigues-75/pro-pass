from smartcard.System import readers
import os
import json
import time

# Clés essayées pour authentifier chaque secteur AVANT écriture.
# On tente chacune (en Clé B puis Clé A) et on garde la première qui marche.
# Cela rend la copie compatible avec les différents badges en circulation
# (clé PROPASS, clé terrain 1KIGIV, clés par défaut) SANS toucher aux cartes.
PASS_OMEGA = [0xEF, 0x61, 0xA3, 0xD4, 0x8E, 0x2A]  # clé PROPASS historique
KEY_1KIGIV = [0x31, 0x4B, 0x49, 0x47, 0x49, 0x56]  # "1KIGIV" (314B49474956) - badges terrain
KEY_DEFAULT = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
KEY_A0 = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5]
KEY_D3 = [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7]
KEY_ZERO = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

KEY_LIST = [PASS_OMEGA, KEY_1KIGIV, KEY_DEFAULT, KEY_A0, KEY_D3, KEY_ZERO]
KEY_TYPES = [0x61, 0x60]  # 0x61 = Clé B d'abord, 0x60 = Clé A ensuite

SOURCE_PATH = os.environ.get(
    "PROPASS_SOURCE_PATH",
    os.path.join(os.path.dirname(__file__), "..", "..", "VAULT", "SOURCE_ZERO.bin")
)


def get_data_block(matrix: bytes, sector: int, block_index: int, compact_768: bool) -> list:
    if compact_768:
        start = ((sector * 3) + block_index) * 16
    else:
        block = (sector * 4) + block_index
        start = block * 16
    return list(matrix[start:start + 16])


def try_auth(conn, base_block, key, key_type):
    """Charge la clé puis tente l'authentification. Retourne True si OK (0x90)."""
    try:
        conn.transmit([0xFF, 0x82, 0x00, 0x00, 0x06] + key)
        _, sw1, _ = conn.transmit([
            0xFF, 0x86, 0x00, 0x00, 0x05,
            0x01, 0x00, base_block, key_type, 0x00
        ])
        return sw1 == 0x90
    except Exception:
        return False


def auth_sector(conn, base_block):
    """Essaie toutes les clés (B puis A) sur le secteur. Retourne (key, key_type) ou None."""
    for key in KEY_LIST:
        for kt in KEY_TYPES:
            if try_auth(conn, base_block, key, kt):
                return (key, kt)
    return None


def write_block(conn, base_block, block, data, current):
    """Écrit un bloc. Si l'écriture est refusée, ré-essaie avec les autres
    clés/types (certaines cartes n'autorisent l'écriture qu'avec la Clé A ou B).
    Retourne True si le bloc est écrit."""
    # 1) tentative avec l'authentification déjà en cours
    try:
        _, sw1_w, _ = conn.transmit([0xFF, 0xD6, 0x00, block, 16] + data)
        if sw1_w == 0x90:
            return True
    except Exception:
        pass
    # 2) ré-essai : on ré-authentifie avec chaque clé/type puis on réécrit
    for key in KEY_LIST:
        for kt in KEY_TYPES:
            if try_auth(conn, base_block, key, kt):
                try:
                    _, sw1_w, _ = conn.transmit([0xFF, 0xD6, 0x00, block, 16] + data)
                    if sw1_w == 0x90:
                        return True
                except Exception:
                    continue
    return False


def main():
    if not os.path.exists(SOURCE_PATH):
        print(f"[-] Erreur : {SOURCE_PATH} absent.")
        return 1

    r = readers()
    if not r:
        print("[-] Materiel absent.")
        return 1

    # Wait for the badge to be on the reader (up to PROPASS_CARD_WAIT_S seconds).
    wait_s = float(os.environ.get('PROPASS_CARD_WAIT_S') or 20)
    deadline = time.time() + wait_s
    conn = r[0].createConnection()
    while True:
        try:
            conn.connect()
            break
        except Exception:
            if time.time() >= deadline:
                print("[-] Connexion lecteur impossible : badge non detecte")
                print(json.dumps({"success": False, "error": "CARD_TIMEOUT"}))
                return 1
            time.sleep(0.3)

    with open(SOURCE_PATH, "rb") as f:
        matrix = f.read()

    matrix_len = len(matrix)
    compact_768 = matrix_len == 768
    full_1024 = matrix_len >= 1024

    if not compact_768 and not full_1024:
        print(f"[-] Dump invalide: taille {matrix_len} bytes (attendu 768 ou >=1024)")
        return 1

    if compact_768:
        print("[i] Dump compact détecté (768 bytes)")

    print("[+] SYNC PRO ALPHA : Mise a jour des supports actifs...")

    had_auth = False
    had_write = False
    had_write_fail = False
    failed_sectors = []

    for sector in range(0, 16):
        print(f"[*] Secteur {sector:02d} :", end=" ")
        base_block = sector * 4

        found = auth_sector(conn, base_block)

        if found:
            had_auth = True
            print("AUTH OK ->", end=" ")
            for i in range(3):
                block = base_block + i
                data = get_data_block(matrix, sector, i, compact_768)

                # Bloc 0 (UID) : toléré s'il ne s'écrit pas (carte non magique).
                if sector == 0 and i == 0:
                    if write_block(conn, base_block, 0, data, found):
                        had_write = True
                        print("B0:W", end=" ")
                    else:
                        print("B0:SKIP", end=" ")
                    continue

                if write_block(conn, base_block, block, data, found):
                    had_write = True
                    print(f"B{block}:W", end=" ")
                else:
                    had_write_fail = True
                    print(f"B{block}:X", end=" ")
            print()
        else:
            print("ECHEC AUTH (Verifier le support)")
            failed_sectors.append(sector)

    print("\n[V] SYNCHRONISATION TERMINEE.")

    if not had_auth:
        return 1
    if not had_write:
        return 1
    if had_write_fail:
        return 1
    if failed_sectors:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
