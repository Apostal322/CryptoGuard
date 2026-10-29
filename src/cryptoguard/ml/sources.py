"""Pinned external label sources: where each file comes from, its hash and its license.

Two of the three sources publish no license, so their files are never redistributed with
CryptoGuard: ``fetch_sources`` downloads them on request into the local data directory
(git-ignored) and refuses any file whose SHA-256 differs from the pinned value.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import httpx

DEFAULT_DATA_DIR = Path("data") / "external"


@dataclass(frozen=True)
class SourceFile:
    path: str
    sha256: str
    size: int


@dataclass(frozen=True)
class Source:
    name: str
    repository: str
    commit: str
    license: str | None  # SPDX id; None = no license published (all rights reserved)
    citation: str
    files: tuple[SourceFile, ...]

    @property
    def redistributable(self) -> bool:
        return self.license is not None

    def url(self, file: SourceFile) -> str:
        return f"https://raw.githubusercontent.com/{self.repository}/{self.commit}/{file.path}"


SOURCES: dict[str, Source] = {
    "ptxphish": Source(
        name="ptxphish",
        repository="HypoopyH/PTXPhish",
        commit="18efed8f8e8eaa6abb36ef94bfec4c06dd744090",
        license=None,
        citation=(
            "Chen, Hu, He, Luo, Wu, Zhou. Dissecting Payload-based Transaction Phishing on "
            "Ethereum. NDSS 2025."
        ),
        files=(
            SourceFile(
                "dataset/PTXPHISH.xlsx",
                "a5bdc03757963d22a58b755caf08f058530658c34b5b38af428af0ee35b38ce0",
                897_414,
            ),
            SourceFile(
                "dataset/InitialAddress.xlsx",
                "2b8a8cd6c9a9b70b16c14eb15310650ca07c8be0c09c0a3bba8ca39f0a84785a",
                28_127,
            ),
        ),
    ),
    "poison-hunter": Source(
        name="poison-hunter",
        repository="DS2L/Poison-Hunter",
        commit="74ff6f7d14f196a7396d7aa0b88aecd9a3bd9ff0",
        license=None,
        citation="Guan, Li. Characterizing Ethereum Address Poisoning Attack. ACM CCS 2024.",
        files=(
            SourceFile(
                "benign_addresses_on_etherscan.txt",
                "301cd31f4280cef85a1075f0da1dd390d05cc2c7c90a2020a4cbb9bc982fc3a1",
                49_622,
            ),
            SourceFile(
                "phishing_address_groundtruth.txt",
                "d0e16888ccea93207ea6387815d0ab75076558524a9d2e7212f22a6855415cbd",
                253_270,
            ),
            SourceFile(
                "phishing_address_we_detected_TP.txt",
                "69fd916960998d3f3e87b517ad4a3e787e1789b7dbaa451cfc0d631cfe2c06c8",
                246_347,
            ),
            SourceFile(
                "phishing_transfers_sample.csv",
                "1de4bf2aa0bdc02e8347eeedf5d843f32e83a3f8e0c7fd864fea1997726fcc84",
                63_454,
            ),
        ),
    ),
    "forta": Source(
        name="forta",
        repository="forta-network/labelled-datasets",
        commit="40a9c2f2bd7e9ddfdd0f3540db589f0288e1e88a",
        license="MIT",
        citation="Forta Network, labelled-datasets (Etherscan phish-hack/exploit/heist labels).",
        files=(
            SourceFile(
                "labels/1/phishing_scams.csv",
                "10fb332f7e79056862900692df3503ef26fa193445b4f2908cecdae2d0c0b3c9",
                525_163,
            ),
            SourceFile(
                "labels/1/etherscan_malicious_labels.csv",
                "9a787753c7caf64d506de755830ac85d05f21973939763251f54c38136505f42",
                678_922,
            ),
            SourceFile(
                "labels/1/malicious_smart_contracts.csv",
                "b2f680720f6dd56158c82ff141aecbea3d9f68e987193e9ea9314da13afdb81e",
                162_717,
            ),
        ),
    ),
}


class SourceIntegrityError(RuntimeError):
    """A downloaded or cached file does not match its pinned hash."""


def local_path(data_dir: Path, source: Source, file: SourceFile) -> Path:
    return data_dir / source.name / file.path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(data_dir: Path, source: Source) -> list[Path]:
    """Return the source's local files, raising if one is missing or altered."""
    paths = []
    for file in source.files:
        path = local_path(data_dir, source, file)
        if not path.exists():
            raise FileNotFoundError(f"{path} is missing; run `cryptoguard ml fetch-sources`.")
        if (digest := sha256_file(path)) != file.sha256:
            raise SourceIntegrityError(f"{path}: sha256 {digest} != pinned {file.sha256}")
        paths.append(path)
    return paths


def fetch_sources(
    data_dir: Path = DEFAULT_DATA_DIR,
    names: tuple[str, ...] | None = None,
    *,
    client: httpx.Client | None = None,
) -> list[tuple[str, str, str]]:
    """Download missing files at their pinned commits; verify every file. Returns
    (source, path, status) rows."""
    rows = []
    own = client is None
    http = client or httpx.Client(timeout=60, follow_redirects=True)
    try:
        for name in names or tuple(SOURCES):
            source = SOURCES[name]
            for file in source.files:
                path = local_path(data_dir, source, file)
                if path.exists() and sha256_file(path) == file.sha256:
                    rows.append((name, file.path, "cached"))
                    continue
                data = http.get(source.url(file)).raise_for_status().content
                if (digest := hashlib.sha256(data).hexdigest()) != file.sha256:
                    raise SourceIntegrityError(
                        f"{source.url(file)}: sha256 {digest} != pinned {file.sha256}"
                    )
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                rows.append((name, file.path, "downloaded"))
    finally:
        if own:
            http.close()
    return rows
