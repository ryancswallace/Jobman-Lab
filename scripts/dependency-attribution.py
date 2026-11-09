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
from pathlib import Path

from attribution_sources import bound_file, checked_zip, module_source, verify_export
from evaluation import new_output, read_manifest


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
NOTICE = re.compile(r"^(license|licence|notice|copying|copyright|patents|third[._-]party[._-](?:licenses?|notices?))(?:$|[._-])", re.I)
TEXT_SUFFIXES = {"", ".txt", ".md", ".markdown", ".rst", ".html", ".htm"}
BUILD_FILES = ("GoFiles", "CgoFiles", "SFiles", "CFiles", "CXXFiles", "HFiles", "SysoFiles", "EmbedFiles")
HELPERS = {"rolldown/runtime.js": "node_modules/rolldown",
           "vite/modulepreload-polyfill.js": "node_modules/vite",
           "vite/preload-helper.js": "node_modules/vite"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked_file(path, expected):
    data = path.read_bytes()
    if digest(data) != expected:
        raise ValueError(f"pinned digest differs for {path.name}")
    return data


def run_go(args, cwd=None, **settings):
    env = dict(os.environ, GOENV="off", GOWORK="off", GOFLAGS="", **settings)
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
        if file.is_file() and NOTICE.match(file.name) and file.suffix.lower() in TEXT_SUFFIXES
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


def go_executable(binary, source, source_hashes, commit, platform, archive_docs, build_revision, notices):
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
    if f"{settings['GOOS']}/{settings['GOARCH']}" != platform or settings["CGO_ENABLED"] != "0":
        raise ValueError(f"unexpected release target for {binary.name}")
    go_env = {
        "GOOS": settings["GOOS"], "GOARCH": settings["GOARCH"],
        "CGO_ENABLED": settings["CGO_ENABLED"], "GOTOOLCHAIN": toolchain,
    }
    for key in ("GOAMD64", "GOARM64", "GOEXPERIMENT"):
        go_env[key] = settings.get(key, "")
    entry = "." + build["Path"].removeprefix(build["Main"]["Path"])
    packages = json_stream(run_go(["list", "-mod=readonly", "-deps", "-json", "-tags=" + settings.get("-tags", ""), entry], source, **go_env))
    selected, project_files = {}, set()
    standard_count = 0
    for package in packages:
        if package.get("Standard"):
            standard_count += 1
        module = package.get("Module", {})
        directory = Path(package.get("Dir", source))
        names = [name for kind in BUILD_FILES for name in package.get(kind, [])]
        if module.get("Main"):
            project_files.update((directory / name).relative_to(source).as_posix() for name in names)
        if not module.get("Version"):
            continue
        if module.get("Replace"):
            raise ValueError("local module replacements are outside the release inventory")
        key = (module["Path"], module["Version"])
        root = Path(module["Dir"])
        files = selected.setdefault(key, (root, set()))[1]
        files.update((directory / name).relative_to(root).as_posix() for name in names)
    for name in sorted(project_files):
        bound_file(source, name, source_hashes)
    expected = {(item["Path"], item["Version"]): item for item in build.get("Deps", [])}
    if set(selected) != set(expected):
        raise ValueError(f"linked and selected module lists differ for {binary.name}")
    goroot, cache = map(Path, run_go(["env", "GOROOT", "GOMODCACHE"], source, **go_env).splitlines())
    go_notices = [include_notice(notices, toolchain, name, (goroot / name).read_bytes())
                  for name in ("LICENSE", "PATENTS")]

    modules = []
    for key, (root, files) in sorted(selected.items()):
        path, version = key
        identity = f"{path}@{version}"
        if expected[key].get("Replace") or not expected[key].get("Sum"):
            raise ValueError(f"missing immutable module identity for {identity}")
        hashes, annotations = module_source(cache, path, version, expected[key]["Sum"])
        for filename in sorted(files):
            bound_file(root, filename, hashes)
        parents = {Path(".")}
        for filename in files:
            parents.update(Path(filename).parents)
        paths = [name for name in sorted(hashes) if Path(name).parent in parents
                 and NOTICE.match(Path(name).name) and Path(name).suffix.lower() in TEXT_SUFFIXES]
        if not paths:
            raise ValueError(f"no upstream notices located for {identity}")
        module_notices = []
        for filename in paths:
            data = bound_file(root, filename, hashes)
            notice = include_notice(notices, identity, filename, data)
            notice["includedAsNotice"] = any(normalized(data) in normalized(text) for text in archive_docs.values())
            module_notices.append(notice)
        exceptions = []
        for filename, meaning in EXCEPTIONS.get(path, ()):
            data = bound_file(root, filename, hashes)
            exceptions.append({
                "path": filename, "sha256": digest(data), "interpretation": meaning,
                "selectedBuildInput": filename in files,
                "includedAsNotice": any(normalized(data) in normalized(text) for text in archive_docs.values()),
            })
        modules.append({
            "path": path, "version": version, "goSum": expected[key].get("Sum"),
            "selectedSourceFiles": {name: hashes[name] for name in sorted(files)},
            "notices": module_notices, "exceptionFiles": exceptions,
            "sourceAnnotations": [{"path": name, "sha256": hashes[name], "selectedBuildInput": name in files, **detail}
                                  for name, detail in sorted(annotations.items())],
        })
    return {
        "path": build["Path"], "toolchain": toolchain, "sourceCommit": commit,
        "sourceBinding": "Go VCS build information" if revision else "Authenticated archive build.json",
        "standardLibraryPackages": standard_count, "standardLibraryNotices": go_notices,
        "mainProjectNotices": [include_notice(notices, build["Main"]["Path"], "LICENSE",
                                              bound_file(source, "LICENSE", source_hashes))],
        "modules": modules,
    }


def spdx_evidence(document, executables, archive_docs):
    modules = {}
    for executable, record in executables.items():
        for module in record["modules"]:
            modules.setdefault((module["path"], module["version"]), {})[executable] = module
    extracted = {item["licenseId"]: item for item in document.get("hasExtractedLicensingInfos", [])}
    results, observed = [], set()
    for package in document["packages"]:
        name, version = package["name"], package.get("versionInfo")
        declared = package.get("licenseDeclared")
        concluded = package.get("licenseConcluded")
        module = modules.get((name, version))
        references = set(re.findall(r"\bLicenseRef-([A-Za-z0-9.-]+)", f"{declared} {concluded}"))
        exceptions = [item for record in (module or {}).values() for item in record["exceptionFiles"]]
        if not set(references).issubset({item["sha256"] for item in exceptions}):
            raise ValueError(f"unmapped SPDX license reference for {name}@{version}")
        observed.update("LicenseRef-" + reference for reference in references)
        item = {"name": name, "version": version, "declared": declared, "concluded": concluded, "original": package}
        if module:
            item["sourceNoticeFiles"] = {name: record["notices"] for name, record in module.items()}
            item["referenceFiles"] = {
                name: [{**entry, "original": extracted["LicenseRef-" + entry["sha256"]]}
                       for entry in record["exceptionFiles"] if entry["sha256"] in references]
                for name, record in module.items()
            }
            if "GPL-2.0-only" in (concluded or "") and name == "modernc.org/libc":
                item["nonPermissiveEvidence"] = {
                    name: [entry for entry in record["exceptionFiles"] if entry["path"].endswith("/COPYING")]
                    + record["sourceAnnotations"] for name, record in module.items()
                }
        elif name == "stdlib":
            item["sourceNoticeFiles"] = next(iter(executables.values()))["standardLibraryNotices"]
        elif any(record["path"].startswith(name) for record in executables.values()):
            item["sourceNoticeFiles"] = next(iter(executables.values()))["mainProjectNotices"]
            item["scope"] = "Main project source at the authenticated release commit."
        else:
            item["sourceNoticeFiles"] = [
                {"path": path, "sha256": digest(data)} for path, data in sorted(archive_docs.items())
            ]
            item["scope"] = "Project or aggregate release entry. See the archive and per-executable inventory."
        if item not in results:
            results.append(item)
    if observed != extracted.keys():
        raise ValueError("extracted SPDX license references differ from the mapped package references")
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


def dashboard_web(source, archive, archive_docs, notices, npm_tarballs):
    web = source / "web"
    lock_path = web / "package-lock.json"
    lock_bytes = lock_path.read_bytes()
    lock = json.loads(lock_bytes)["packages"]
    assets = web / "dist" / "assets"
    mapped = {}
    binaries = {}
    for file in sorted(assets.glob("*.js.map")):
        name = file.name.removesuffix(".map")
        member = [item for item in archive.getmembers() if item.name.endswith(f"/assets/{name}")]
        if len(member) != 1 or archive.extractfile(member[0]).read() != (assets / name).read_bytes():
            raise ValueError(f"rebuilt web asset differs from {name} in release")
        binaries[name] = digest((assets / name).read_bytes())
        source_map = json.loads(file.read_bytes())
        for item, content in zip(source_map["sources"], source_map["sourcesContent"], strict=True):
            mapped_file = (assets / item).resolve()
            if not mapped_file.is_relative_to(source.resolve()):
                raise ValueError(f"source map references a file outside pinned source: {item}")
            if not mapped_file.is_relative_to(web.resolve()):
                continue
            path = mapped_file.relative_to(web.resolve()).as_posix()
            package_paths = [key for key in lock if key and path.startswith(key + "/")]
            if package_paths:
                if content is None or mapped_file.read_text(encoding="utf-8") != content:
                    raise ValueError(f"source map content differs for {path}")
                package = max(package_paths, key=len)
                mapped.setdefault(package, set()).add(path.removeprefix(package + "/"))
    published = {Path(member.name).name for member in archive.getmembers()
                 if member.isfile() and "/assets/" in member.name and member.name.endswith(".js")}
    if not published or set(binaries) != published:
        raise ValueError("source maps must account for each released JavaScript asset")
    helpers = {}
    graph_path = web / "dist" / "third-party-web.json"
    if graph_path.is_file():
        graph = json.loads(graph_path.read_bytes())
        if graph.get("schemaVersion") != 1 or graph.get("lockSHA256") != digest(lock_bytes):
            raise ValueError("rendered browser graph differs from the pinned lock")
        for observation in graph["observations"]:
            if observation["kind"] != "injected-helper":
                continue
            name, package = observation["module"], observation["packagePath"]
            if (package != HELPERS.get(name) or package not in lock
                    or not re.fullmatch("[a-f0-9]{64}", observation["renderedSHA256"])):
                raise ValueError(f"unrecognized browser helper {name}")
            helpers.setdefault(package, []).append(observation)
    records = []
    for key, entry in sorted(lock.items()):
        compiled = sorted(mapped.get(key, ()))
        files = []
        if compiled or key in helpers:
            identity = f"{key.rsplit('node_modules/', 1)[-1]}@{entry['version']}"
            paths = notice_paths(web / key)
            if not paths:
                raise ValueError(f"bundled web dependency has no notice files: {identity}")
            for path in paths:
                data = path.read_bytes()
                notice = include_notice(notices, identity, path.name, data)
                notice["includedAsNotice"] = any(normalized(data) in normalized(text) for text in archive_docs.values())
                files.append(notice)
        record = {
            "path": key or "(root)", "version": entry.get("version"),
            "declaredLicense": entry.get("license"), "integrity": entry.get("integrity"),
            "development": entry.get("dev", False), "publishedSources": compiled,
            "injectedHelpers": helpers.get(key, []), "notices": files,
        }
        if entry.get("license") == "MPL-2.0" and not compiled:
            record["buildOrTestNotices"] = npm_build_license(key, entry, npm_tarballs)
        records.append(record)
    return {"lockSHA256": digest(lock_bytes), "verifiedJavaScript": binaries, "packages": records,
            "helperGraphObserved": graph_path.is_file()}


def python_wheels(wheel_directory, requirements, notices):
    def canonical(name):
        return re.sub(r"[-_.]+", "-", name).lower()

    pins, observed, records = {}, set(), []
    for line in requirements.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)", line)
        if not match or canonical(match[1]) in pins:
            raise ValueError("composer requirements must have one exact pin per package")
        pins[canonical(match[1])] = match[2]
    for wheel in sorted(wheel_directory.glob("*.whl")):
        archive, entries = checked_zip(wheel)
        with archive:
            entry, = [name for name in entries if name.endswith(".dist-info/METADATA")]
            metadata_bytes = archive.read(entry)
            metadata = email.message_from_bytes(metadata_bytes)
            name, version = metadata["Name"], metadata["Version"]
            if canonical(name) in observed or pins.get(canonical(name)) != version:
                raise ValueError(f"unexpected wheel {wheel.name}")
            observed.add(canonical(name))
            paths = [path for path in entries
                     if ".dist-info/" in path and not path.endswith("/")
                     and (".dist-info/licenses/" in path or NOTICE.match(Path(path).name))]
            if not paths:
                raise ValueError(f"no packaged notice files in {wheel.name}")
            files = [include_notice(notices, f"{name}=={version}", path.split(".dist-info/")[1], archive.read(path))
                     for path in sorted(paths)]
        records.append({
            "name": name, "version": version, "wheel": wheel.name, "wheelSHA256": digest(wheel.read_bytes()),
            "metadataSHA256": digest(metadata_bytes),
            "declaredLicense": metadata["License-Expression"] or metadata["License"], "notices": files,
        })
    if observed != pins.keys():
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
    cli.add_argument("--source-repositories", type=Path, required=True,
                     help="Directory containing the four repositories with the selected commits")
    cli.add_argument("--wheels", type=Path, required=True)
    cli.add_argument("--npm-tarballs", type=Path, required=True)
    cli.add_argument("--requirements", type=Path, required=True)
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    selection = read_manifest(args.inputs / "selection.json")
    receipt = json.loads((args.inputs / "verification.json").read_bytes())
    if receipt["platform"] != selection["platform"]:
        raise ValueError("verification receipt platform differs")
    inventory = {"schemaVersion": 2, "platform": selection["platform"], "products": {},
                 "technicalAttributionOwner": "ryancswallace"}
    all_notices, originals = {}, {}
    for name, product in selection["products"].items():
        directory = args.inputs / name
        source = args.sources / f"{name}-release"
        source_hashes = verify_export(args.source_repositories / product["repository"].split("/")[1].lower(),
                                      product["commit"], source)
        recorded = receipt["products"][name]
        if recorded["commit"] != product["commit"] or recorded["version"] != product["version"] or any(
            recorded[field + "SHA256"] != product[field]["sha256"] for field in ("archive", "sbom")
        ):
            raise ValueError(f"verification receipt differs for {name}")
        archive_path = directory / product["archive"]["name"]
        checked_file(archive_path, product["archive"]["sha256"])
        checked_file(directory / product["checksums"]["name"], product["checksums"]["sha256"])
        originals[name] = checked_file(directory / product["sbom"]["name"], product["sbom"]["sha256"])
        sbom = json.loads(originals[name])
        if sbom.get("spdxVersion") != "SPDX-2.3":
            raise ValueError(f"unexpected SPDX format for {name}")
        notices = {}
        executables = {}
        with tarfile.open(archive_path) as archive:
            docs = archive_notices(archive)
            build_info = [item for item in archive.getmembers() if item.name.endswith("/build.json")]
            build_revision = json.load(archive.extractfile(build_info[0]))["revision"] if len(build_info) == 1 else None
            for command, executable in product["executables"].items():
                if recorded["executables"][command] != executable["sha256"]:
                    raise ValueError(f"verification receipt differs for {command}")
                binary = args.inputs / "bin" / command
                data = checked_file(binary, executable["sha256"])
                member = [item for item in archive.getmembers()
                          if item.name.removeprefix("./") == executable["path"]]
                if len(member) != 1 or archive.extractfile(member[0]).read() != data:
                    raise ValueError(f"archive binary differs for {command}")
                record = go_executable(binary, source, source_hashes, product["commit"], selection["platform"],
                                       docs, build_revision, notices)
                record["sha256"] = executable["sha256"]
                executables[command] = record
            if name == "dashboard":
                inventory["dashboardWeb"] = dashboard_web(source, archive, docs, notices, args.npm_tarballs)
        inventory["products"][name] = {
            "version": product["version"], "commit": product["commit"], "archive": product["archive"],
            "authenticatedSPDX": product["sbom"], "executables": executables,
            "archiveNoticeMembers": {path: digest(data) for path, data in docs.items()},
            "spdxEvidence": spdx_evidence(sbom, executables, docs),
        }
        all_notices[name] = notices
    notices = {}
    inventory["composerPython"] = python_wheels(args.wheels, args.requirements, notices)
    all_notices["composer"] = notices
    new_output(args.output)
    original_dir = args.output / "original-spdx"
    original_dir.mkdir()
    for name, data in originals.items():
        (original_dir / f"{name}.json").write_bytes(data)
    for name, notices in all_notices.items():
        write_notices(args.output, name, notices)
    (args.output / "dependency-attribution.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
