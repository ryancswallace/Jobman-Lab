#!/usr/bin/env python3
"""Resolve the pinned release evaluation inventory against build inputs."""

import argparse
import base64
import email
import hashlib
import json
import os
import re
import subprocess
import tarfile
import urllib.parse
import zipfile
from pathlib import Path


EXCEPTIONS = {
    "modernc.org/libc": [
        ("LICENSE-3RD-PARTY.md", "Source notice for generated and test components"),
        ("testdata/nsz.repo.hu/libc-test/src/math/crlibm/COPYING", "GPL-2.0-only test corpus license"),
    ],
    "modernc.org/memory": [("LICENSE-LOGO", "License statement for the repository logo")],
    "modernc.org/sqlite": [
        ("LICENSE-3RD-PARTY.md", "Source notice with component-specific terms"),
        ("LICENSE-SQLITE", "Upstream SQLite public-domain statement"),
    ],
    "github.com/coreos/go-oidc/v3": [("NOTICE", "Upstream Apache attribution notice")],
    "github.com/jackc/pgx/v5": [
        ("pgproto3/notice_response.go", "PostgreSQL protocol source file covered by the module's MIT license"),
    ],
}
NOTICE = re.compile(r"^(license|licence|notice|copying|copyright|patents)(?:$|[._-])", re.I)
BUILD_FILES = ("GoFiles", "CgoFiles", "SFiles", "CFiles", "CXXFiles", "HFiles", "SysoFiles", "EmbedFiles")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked_file(path, expected):
    data = path.read_bytes()
    if digest(data) != expected:
        raise ValueError(f"pinned digest differs for {path.name}")
    return data


def run_go(args, cwd=None, **settings):
    env = dict(os.environ, GOENV="off", GOWORK="off", **settings)
    env.pop("GOROOT", None)
    return subprocess.check_output(["go", *args], cwd=cwd, env=env, text=True)


def json_stream(data):
    decoder = json.JSONDecoder()
    data = data.lstrip()
    while data:
        item, end = decoder.raw_decode(data)
        yield item
        data = data[end:].lstrip()


def notice_paths(directory):
    return [
        file
        for file in sorted(directory.iterdir())
        if file.is_file() and NOTICE.match(file.name) and file.suffix != ".go"
    ]


def archive_notices(archive):
    result = {}
    for member in archive.getmembers():
        name = Path(member.name).name
        if member.isfile() and (NOTICE.match(name) or name == "THIRD_PARTY_NOTICES.md"):
            result[member.name] = archive.extractfile(member).read()
    return result


def normalized(data):
    return b" ".join(data.split())


def include_notice(notices, identity, name, data):
    key = (identity, name)
    if key in notices and notices[key] != data:
        raise ValueError(f"inconsistent notice for {identity} {name}")
    notices[key] = data
    return {"path": name, "sha256": digest(data)}


def go_executable(binary, source, commit, archive_docs, build_revision, notices):
    build = json.loads(run_go(["version", "-m", "-json", str(binary)]))
    settings = {item["Key"]: item.get("Value", "") for item in build["Settings"]}
    revision = settings.get("vcs.revision")
    if (revision != commit or settings.get("vcs.modified") != "false") and (
        revision is not None or build_revision != commit
    ):
        raise ValueError(f"{binary.name} has unexpected release source")
    toolchain = build["GoVersion"]
    if not re.fullmatch(r"go1\.[0-9]+\.[0-9]+", toolchain):
        raise ValueError(f"unexpected toolchain for {binary.name}")
    go_env = {
        "GOOS": settings["GOOS"], "GOARCH": settings["GOARCH"],
        "CGO_ENABLED": settings["CGO_ENABLED"], "GOTOOLCHAIN": toolchain,
    }
    entry = "." + build["Path"].removeprefix(build["Main"]["Path"])
    packages = json_stream(run_go(["list", "-mod=readonly", "-deps", "-json", entry], source, **go_env))
    selected = {}
    standard_count = 0
    for package in packages:
        if package.get("Standard"):
            standard_count += 1
        module = package.get("Module", {})
        if not module.get("Version"):
            continue
        if module.get("Replace"):
            raise ValueError("local module replacements are outside the release inventory")
        key = (module["Path"], module["Version"])
        root = Path(module["Dir"])
        files = selected.setdefault(key, (root, set()))[1]
        directory = Path(package["Dir"])
        files.update((directory / name).relative_to(root).as_posix()
                     for kind in BUILD_FILES for name in package.get(kind, []))
    expected = {(item["Path"], item["Version"]): item for item in build.get("Deps", [])}
    if set(selected) != set(expected):
        raise ValueError(f"linked and selected module lists differ for {binary.name}")
    goroot = Path(run_go(["env", "GOROOT"], source, **go_env).strip())
    go_notices = [include_notice(notices, toolchain, name, (goroot / name).read_bytes())
                  for name in ("LICENSE", "PATENTS")]

    modules = []
    for key, (root, files) in sorted(selected.items()):
        path, version = key
        identity = f"{path}@{version}"
        paths = notice_paths(root)
        if not paths:
            raise ValueError(f"no upstream root notices located for {identity}")
        module_notices = [include_notice(notices, identity, file.name, file.read_bytes()) for file in paths]
        exceptions = []
        for filename, meaning in EXCEPTIONS.get(path, ()):
            data = (root / filename).read_bytes()
            exceptions.append({
                "path": filename, "sha256": digest(data), "interpretation": meaning,
                "selectedBuildInput": filename in files,
                "includedAsNotice": any(normalized(data) in normalized(text) for text in archive_docs.values()),
            })
        modules.append({
            "path": path, "version": version, "goSum": expected[key].get("Sum"),
            "selectedSourceFiles": len(files), "notices": module_notices, "exceptionFiles": exceptions,
        })
    return {
        "path": build["Path"], "toolchain": toolchain, "sourceCommit": commit,
        "sourceBinding": "Go VCS build information" if revision else "Authenticated archive build.json",
        "standardLibraryPackages": standard_count, "standardLibraryNotices": go_notices,
        "modules": modules,
    }


def spdx_evidence(document, executables, archive_docs):
    modules = {
        (mod["path"], mod["version"]): mod
        for exe in executables.values() for mod in exe["modules"]
    }
    results = []
    for package in document["packages"]:
        name, version = package["name"], package.get("versionInfo")
        declared = package.get("licenseDeclared")
        concluded = package.get("licenseConcluded")
        module = modules.get((name, version))
        references = re.findall(r"LicenseRef-([0-9a-f]{64})", concluded or "")
        exceptions = module["exceptionFiles"] if module else []
        if not set(references).issubset({item["sha256"] for item in exceptions}):
            raise ValueError(f"unmapped SPDX license reference for {name}@{version}")
        item = {"name": name, "version": version, "declared": declared, "concluded": concluded}
        if module:
            item["sourceNoticeFiles"] = module["notices"]
            item["referenceFiles"] = [entry for entry in exceptions if entry["sha256"] in references]
            if "GPL-2.0-only" in (concluded or "") and name == "modernc.org/libc":
                item["nonPermissiveDetection"] = next(
                    entry for entry in exceptions if entry["path"].endswith("/COPYING")
                )
        elif name == "stdlib":
            item["sourceNoticeFiles"] = next(iter(executables.values()))["standardLibraryNotices"]
        else:
            item["sourceNoticeFiles"] = [
                {"path": path, "sha256": digest(data)} for path, data in sorted(archive_docs.items())
            ]
            item["scope"] = "Project or aggregate release entry. See the archive and per-executable inventory."
        if item not in results:
            results.append(item)
    return results


def npm_build_license(key, entry, tarballs):
    url = urllib.parse.urlsplit(entry["resolved"])
    if url.scheme != "https" or url.hostname != "registry.npmjs.org":
        raise ValueError(f"unexpected registry for {key}")
    path = tarballs / Path(url.path).name
    content = path.read_bytes()
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(content).digest()).decode("ascii")
    if integrity != entry["integrity"]:
        raise ValueError(f"lock integrity differs for {key}")
    with tarfile.open(path) as bundle:
        metadata = json.load(bundle.extractfile("package/package.json"))
        expected = key.rsplit("node_modules/", 1)[-1]
        if metadata["name"] != expected or metadata["version"] != entry["version"]:
            raise ValueError(f"lock package identity differs for {key}")
        licenses = [{"path": item.name, "sha256": digest(bundle.extractfile(item).read())}
                    for item in bundle.getmembers() if item.isfile() and NOTICE.match(Path(item.name).name)]
    if not licenses:
        raise ValueError(f"build license not found for {key}")
    return licenses


def dashboard_web(source, archive, notices, npm_tarballs):
    web = source / "web"
    lock_path = web / "package-lock.json"
    lock = json.loads(lock_path.read_bytes())["packages"]
    assets = web / "dist" / "assets"
    mapped = {}
    binaries = {}
    for file in sorted(assets.glob("*.js.map")):
        name = file.name.removesuffix(".map")
        member = [item for item in archive.getmembers() if item.name.endswith(f"/assets/{name}")]
        if len(member) != 1 or archive.extractfile(member[0]).read() != (assets / name).read_bytes():
            raise ValueError(f"rebuilt web asset differs from {name} in release")
        binaries[name] = digest((assets / name).read_bytes())
        for item in json.loads(file.read_bytes())["sources"]:
            mapped_file = (assets / item).resolve()
            if not mapped_file.is_relative_to(source.resolve()):
                raise ValueError(f"source map references a file outside pinned source: {item}")
            if not mapped_file.is_relative_to(web.resolve()):
                continue
            path = mapped_file.relative_to(web.resolve()).as_posix()
            package_paths = [key for key in lock if key and path.startswith(key + "/")]
            if package_paths:
                package = max(package_paths, key=len)
                mapped.setdefault(package, set()).add(path.removeprefix(package + "/"))
    published = {Path(member.name).name for member in archive.getmembers()
                 if member.isfile() and "/assets/" in member.name and member.name.endswith(".js")}
    if not published or set(binaries) != published:
        raise ValueError("source maps must account for each released JavaScript asset")
    records = []
    for key, entry in sorted(lock.items()):
        compiled = sorted(mapped.get(key, ()))
        files = []
        if compiled:
            identity = f"{key.rsplit('node_modules/', 1)[-1]}@{entry['version']}"
            paths = notice_paths(web / key)
            if not paths:
                raise ValueError(f"bundled web dependency has no notice files: {identity}")
            files = [include_notice(notices, identity, path.name, path.read_bytes()) for path in paths]
        record = {
            "path": key or "(root)", "version": entry.get("version"),
            "declaredLicense": entry.get("license"), "integrity": entry.get("integrity"),
            "development": entry.get("dev", False), "publishedSources": compiled, "notices": files,
        }
        if entry.get("license") == "MPL-2.0" and not compiled:
            record["buildOrTestNotices"] = npm_build_license(key, entry, npm_tarballs)
        records.append(record)
    return {"lockSHA256": digest(lock_path.read_bytes()), "verifiedJavaScript": binaries, "packages": records}


def python_wheels(wheel_directory, requirements, notices):
    pins = dict(line.lower().replace("_", "-").split("==", 1)
                for line in requirements.read_text().splitlines()
                if line.strip() and not line.startswith("#"))
    records = []
    for wheel in sorted(wheel_directory.glob("*.whl")):
        with zipfile.ZipFile(wheel) as archive:
            entry, = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
            metadata = email.message_from_bytes(archive.read(entry))
            name, version = metadata["Name"], metadata["Version"]
            if pins.get(name.lower().replace("_", "-")) != version:
                raise ValueError(f"unexpected wheel {wheel.name}")
            paths = [path for path in archive.namelist()
                     if ".dist-info/" in path and not path.endswith("/")
                     and (".dist-info/licenses/" in path or NOTICE.match(Path(path).name))]
            if not paths:
                raise ValueError(f"no packaged notice files in {wheel.name}")
            files = [include_notice(notices, f"{name}=={version}", path.split(".dist-info/")[1], archive.read(path))
                     for path in sorted(paths)]
        records.append({
            "name": name, "version": version, "wheel": wheel.name, "wheelSHA256": digest(wheel.read_bytes()),
            "declaredLicense": metadata["License-Expression"] or metadata["License"], "notices": files,
        })
    if {record["name"].lower().replace("_", "-") for record in records} != pins.keys():
        raise ValueError("wheel inventory does not cover all requirements")
    return {"requirementsSHA256": digest(requirements.read_bytes()), "packages": records}


def write_notices(output, project, notices):
    lines = ["# Third-party notices", "", f"Upstream notices for the {project} release dependency selection.",
             "Each dependency retains its own license terms.", ""]
    for (identity, name), data in sorted(notices.items()):
        lines.extend([f"## {identity} · {name}", ""])
        lines.extend(("    " + line if line else "") for line in data.decode("utf-8").splitlines())
        lines.append("")
    (output / f"{project}-notices.md").write_text("\n".join(lines), encoding="utf-8")


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--inputs", type=Path, required=True)
    cli.add_argument("--sources", type=Path, required=True)
    cli.add_argument("--wheels", type=Path, required=True)
    cli.add_argument("--npm-tarballs", type=Path, required=True)
    cli.add_argument("--requirements", type=Path, required=True)
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    args.output.mkdir(mode=0o700)
    selection = json.loads((args.inputs / "selection.json").read_bytes())
    inventory = {"schemaVersion": 1, "platform": selection["platform"], "products": {}}
    for name, product in selection["products"].items():
        directory = args.inputs / name
        source = args.sources / f"{name}-release"
        archive_path = directory / product["archive"]["name"]
        checked_file(archive_path, product["archive"]["sha256"])
        sbom = json.loads(checked_file(directory / product["sbom"]["name"], product["sbom"]["sha256"]))
        notices = {}
        executables = {}
        with tarfile.open(archive_path) as archive:
            docs = archive_notices(archive)
            build_info = [item for item in archive.getmembers() if item.name.endswith("/build.json")]
            build_revision = json.load(archive.extractfile(build_info[0]))["revision"] if len(build_info) == 1 else None
            for command, executable in product["executables"].items():
                binary = args.inputs / "bin" / command
                data = checked_file(binary, executable["sha256"])
                member = [item for item in archive.getmembers()
                          if item.name.removeprefix("./") == executable["path"]]
                if len(member) != 1 or archive.extractfile(member[0]).read() != data:
                    raise ValueError(f"archive binary differs for {command}")
                record = go_executable(binary, source, product["commit"], docs, build_revision, notices)
                record["sha256"] = executable["sha256"]
                executables[command] = record
            if name == "dashboard":
                inventory["dashboardWeb"] = dashboard_web(source, archive, notices, args.npm_tarballs)
        inventory["products"][name] = {
            "version": product["version"], "commit": product["commit"], "archive": product["archive"],
            "authenticatedSPDX": product["sbom"], "executables": executables,
            "archiveNoticeMembers": {path: digest(data) for path, data in docs.items()},
            "spdxEvidence": spdx_evidence(sbom, executables, docs),
        }
        write_notices(args.output, name, notices)
    notices = {}
    inventory["composerPython"] = python_wheels(args.wheels, args.requirements, notices)
    write_notices(args.output, "composer", notices)
    (args.output / "dependency-attribution.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
