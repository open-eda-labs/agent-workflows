import hashlib
import pathlib

# Cópia de triage-contract@74e5512c7b78f624a81f3ce49d1f437c265b5ee8 (schemas/alert-event.yaml e recommendation.yaml, cada um com 1 linha de cabeçalho).
# Ao atualizar a cópia, troque o commit acima e o hash juntos; sem isso a cópia diverge da origem em silêncio.
SHA256 = "4c20c9beac50d822ca7346a9f30caea33d268c7eb06d82255f2dc3a7587107ce"


def test_contract_copy_matches_pinned_origin():
    h = hashlib.sha256()
    for f in sorted((pathlib.Path(__file__).parent / "contract").iterdir()):
        h.update(f.name.encode() + f.read_bytes())
    assert h.hexdigest() == SHA256
