import json
import os
import sys
import time

import requests

# Cross-platform: msvcrt is Windows-only
if sys.platform == "win32":
    import msvcrt
else:
    msvcrt = None

from app.cowrie_mapper import map_cowrie_to_otori

API = "http://127.0.0.1:8000/ingest"
FILE = os.path.join("data", "cowrie.json")


def post_event(e: dict):
    r = requests.post(API, json=e, timeout=3)
    if r.status_code != 200:
        raise RuntimeError(f"POST {API} -> {r.status_code} {r.text[:200]}")


def open_shared_read(path: str):
    """
    Ouvre le fichier en lecture avec partage (Windows-friendly),
    pour éviter de bloquer l'écriture par VS Code / autres.
    """
    f = open(path, encoding="utf-8", errors="ignore")  # noqa: SIM115
    # Windows: force text mode for shared access
    if msvcrt is not None:
        import contextlib

        with contextlib.suppress(Exception):
            msvcrt.setmode(f.fileno(), os.O_TEXT)
    return f


def stream_bootstrap_and_follow(path: str):
    """
    1) BOOTSTRAP: lit tout le fichier existant (depuis le début)
    2) LIVE: suit les nouvelles lignes (tail)
    Gère remplacement/troncature.
    """
    last_size = -1
    f = None
    bootstrapped = False

    while True:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            time.sleep(0.5)
            continue

        size = st.st_size

        # open si besoin
        if f is None:
            f = open_shared_read(path)
            # bootstrap: lire depuis le début
            if not bootstrapped:
                f.seek(0, os.SEEK_SET)
            else:
                f.seek(0, os.SEEK_END)
            last_size = size

        # fichier remplacé / truncaté
        if size < last_size:
            import contextlib

            with contextlib.suppress(OSError):
                f.close()
            f = open_shared_read(path)
            # après remplacement, on lit depuis le début (au cas où)
            f.seek(0, os.SEEK_SET)
            bootstrapped = False

        last_size = size

        line = f.readline()
        if not line:
            # si bootstrap pas fini, on le marque fini quand on atteint EOF
            if not bootstrapped:
                bootstrapped = True
                # après bootstrap, on se met en tail
                f.seek(0, os.SEEK_END)
            time.sleep(0.25)
            continue

        yield line


def main():
    """Entry point for `otori-stream` command."""
    print("[stream] cwd :", os.getcwd())
    print("[stream] file:", os.path.abspath(FILE))
    print(f"[stream] BOOTSTRAP + LIVE -> {API}")

    for line in stream_bootstrap_and_follow(FILE):
        line = line.strip()
        if not line:
            continue

        try:
            cowrie_event = json.loads(line)
        except Exception:
            continue

        otori_event = map_cowrie_to_otori(cowrie_event)
        if not otori_event:
            continue

        try:
            post_event(otori_event)
        except Exception as ex:
            print("[stream] POST failed:", ex)
            time.sleep(1)


if __name__ == "__main__":
    main()
