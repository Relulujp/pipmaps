#!/usr/bin/env python3
"""PRをAIがマージしてよいかを、変更の危険度（段）と残された証拠で機械的に決める。

仕様：system/specs/delivery.md。段の表：system/delivery/tiers.json。本人の公開鍵：system/owner/owner-key.json。
表・鍵・この検査器は、CIでは基準（base）側の版を使う。PRの中で弱めても、そのPRには効かない。

  T0  CIが緑ならよい
  T1  そのPRの最新コミットに対する、独立した監査の記録（PRのコメント）が要る
  T2  そのPRの最新コミットに対する、本人の署名（Windows Hello）つき承認（PRのコメント）が要る

  python3 tools/delivery_gate.py --base <sha> --head <sha> [--comments comments.json]
  python3 tools/delivery_gate.py --base <sha> --head <sha> --repo owner/name --pr 12 [--post-status]
  python3 tools/delivery_gate.py --repo owner/name --merge 12        # 関門が通したPRだけをマージ
  python3 tools/delivery_gate.py --repo owner/name --watch          # 事後の全件照合（照合の起点から）

終了コード：0=マージしてよい、1=証拠が足りない、2=判定できない（読めない・壊れている）、3=状態を付けられなかった。2を通過と扱わない。
"""
import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from asteria_engine.owner_presence import GRANT_PREFIX, canonical, rsa_verify  # noqa: E402
except ImportError:  # 他のリポジトリへ配った写し（.asteria/）では、同じ場所の owner_presence.py を使う
    from owner_presence import GRANT_PREFIX, canonical, rsa_verify  # noqa: E402

# 段の表と本人の公開鍵の置き場所。asteria は system/ に、配った先のリポジトリは .asteria/ に置く。
LAYOUTS = (("system/delivery/tiers.json", "system/owner/owner-key.json"),
           (".asteria/tiers.json", ".asteria/owner-key.json"))
POLICY, KEY = LAYOUTS[0]


def layout(root, rev):
    """そのコミットにある段の表と鍵の場所。どちらも無ければ None。両方あれば判定しない。

    置き場所が二つあると、弱い表をもう一方へ植えて先に読ませる経路になる（2026-10-03 独立監査）。
    """
    found = [(policy, key) for policy, key in LAYOUTS
             if subprocess.run(["git", "cat-file", "-e", f"{rev}:{policy}"], cwd=root, capture_output=True).returncode == 0]
    if len(found) > 1:
        raise Undecidable("段の表が二つの置き場所にある（system/ と .asteria/）")
    return found[0] if found else None


def read_policy(root, rev):
    found = layout(root, rev)
    if not found:
        raise Undecidable("段の表が無い")
    try:
        return json.loads(git(root, "show", f"{rev}:{found[0]}")), found
    except ValueError:
        raise Undecidable("段の表が壊れている")
AUDIT_TAG = "asteria-audit"
OWNER_TAG = "asteria-owner-approval"
OWNER_KIND = "change-merge"
STATUS_CONTEXT = "asteria/delivery-gate"
BLOCK = re.compile(r"```(asteria-audit|asteria-owner-approval)\s*\n(.*?)\n```", re.S)


class Undecidable(Exception):
    """判定できない。通過として扱わない。"""


def git(root, *args):
    run = subprocess.run(["git", "-c", "core.quotepath=off", *args], cwd=root, capture_output=True,
                         text=True, encoding="utf-8", errors="replace")
    if run.returncode:
        raise Undecidable(f"git {args[0]} failed")
    return run.stdout


SPECIAL_MODES = {"120000": "シンボリックリンク", "160000": "サブモジュール"}


def changes(root, base, head):
    """[(状態, パス, 追加行, 削除行, 特殊)]。名前はNUL区切りで読む。改名・複製は新旧の両方を数え、改名の旧パスは削除として扱う。"""
    status, special = {}, {}
    fields = git(root, "diff", "--raw", "-z", "-M", f"{base}...{head}").split("\0")
    i = 0
    while i < len(fields):
        meta = fields[i].split()
        if len(meta) < 5 or not meta[0].startswith(":"):
            i += 1
            continue
        old_mode, new_mode, state = meta[0][1:], meta[1], meta[4][0]
        count = 2 if state in "RC" else 1
        paths = fields[i + 1:i + 1 + count]
        i += 1 + count
        for n, path in enumerate(paths):
            status[path] = "D" if state == "R" and n == 0 else state
            mode = SPECIAL_MODES.get(new_mode) or SPECIAL_MODES.get(old_mode)
            if mode:
                special[path] = mode
    numbers = {}
    for field in git(root, "diff", "--numstat", "-z", "--no-renames", f"{base}...{head}").split("\0"):
        parts = field.split("\t", 2)
        if len(parts) == 3:
            added, deleted, path = parts
            numbers[path] = (int(added) if added.isdigit() else 0, int(deleted) if deleted.isdigit() else 0)
    return [(state, path, *numbers.get(path, (0, 0)), special.get(path)) for path, state in status.items()]


def tier_of(path, policy):
    # 大文字小文字を区別しない（Windowsの作業木では AGENTS.md と agents.md が同じファイルになる）。安全側にだけ動く。
    path = path.casefold()
    for tier in policy["order"]:
        for pattern in policy["tiers"][tier]["paths"]:
            pattern = pattern.casefold()
            if fnmatch.fnmatchcase(path, pattern) or (pattern.startswith("**/") and fnmatch.fnmatchcase(path, pattern[3:])):
                return tier
    return policy["default"]


def classify(items, policy):
    order = policy["order"]
    if not items:
        return "T0", {}, []
    files = {path: ("T2" if special else tier_of(path, policy)) for _, path, _, _, special in items}
    tier = min(files.values(), key=order.index)
    reasons = [f"{path} は{special}（T2）" for _, path, _, _, special in items if special]
    bump = policy.get("bump", {})
    deleted_files = sum(1 for item in items if item[0] == "D")
    added = sum(item[2] for item in items)
    deleted = sum(item[3] for item in items)
    if deleted_files >= bump.get("deleted_files", 10 ** 9) or (
            deleted and deleted / (added + deleted) >= bump.get("deleted_line_ratio", 2) and deleted >= 20):
        reasons.append(f"削除が多い（ファイル{deleted_files}件、行{deleted}/{added + deleted}）")
        tier = order[max(0, order.index(tier) - 1)]
    return tier, files, reasons


def manifest_from_tree(root, rev, template):
    """そのコミットの木から、目録（package.manifest.json）を作り直す。tools/asteria.py verify と同じ範囲
    （変わってよい場所・.git・目録自身を除く全ファイルのSHA-256）を、作業木ではなく git の中身で数える。
    シンボリックリンク・サブモジュールがあれば作らない（verify がそれを扱わないため）。"""
    mutable = {name.casefold() for name in template.get("mutable_roots", [])}
    entries = {}
    for line in git(root, "ls-tree", "-r", "-z", "--full-tree", rev).split("\0"):
        if not line:
            continue
        meta, path = line.split("\t", 1)
        mode, kind, oid = meta.split()
        if path.split("/")[0].casefold() in mutable | {".git"} or path == "package.manifest.json":
            continue
        if kind != "blob" or mode not in ("100644", "100755"):
            raise Undecidable(f"目録に入れられない種類のファイル：{path}")
        entries[path] = oid
    oids = sorted(set(entries.values()))
    out = subprocess.run(["git", "cat-file", "--batch"], cwd=root, input="".join(o + "\n" for o in oids).encode(),
                         capture_output=True)
    if out.returncode:
        raise Undecidable("git cat-file failed")
    digests, data, i = {}, out.stdout, 0
    for oid in oids:
        header_end = data.index(b"\n", i)
        size = int(data[i:header_end].split()[2])
        digests[oid] = hashlib.sha256(data[header_end + 1:header_end + 1 + size]).hexdigest()
        i = header_end + 1 + size + 1
    try:
        references = len(json.loads(git(root, "show", f"{rev}:reference/provenance.json"))["files"])
    except (ValueError, KeyError, TypeError):
        raise Undecidable("reference/provenance.json を読めない")
    return {**template, "files": {p: digests[o] for p, o in sorted(entries.items())}, "reference_files": references}


def derived_manifest_ok(root, base, head, items, policy):
    """目録だけを変え、その中身が head の木から機械的に作り直した物と一致するPRか。
    目録は main の中身から導ける写しなので、作り直しと一致すれば人の判断は要らない。
    目録の外側の設定（変わってよい場所・版など）は基準側から変えさせない。"""
    target = policy.get("derived_manifest")
    if not target or [(state, path) for state, path, *_ in items] != [("M", target)]:
        return False
    # head が基準（マージ先の今の先端）から直接分かれている時だけ。古い main から分かれた目録は、
    # マージ後の main の木を表さない（2026-10-03 独立監査）
    if subprocess.run(["git", "merge-base", "--is-ancestor", base, head], cwd=root, capture_output=True).returncode:
        return False
    try:  # 読めない・重複キー・作り直せない時は、この例外を使わず元の段（T2）のままにする
        old = json.loads(git(root, "show", f"{base}:{target}"), object_pairs_hook=_no_duplicates)
        new = json.loads(git(root, "show", f"{head}:{target}"), object_pairs_hook=_no_duplicates)
        if not isinstance(old, dict) or not isinstance(new, dict):
            return False
        template = {k: v for k, v in new.items() if k not in ("files", "reference_files")}
        if template != {k: v for k, v in old.items() if k not in ("files", "reference_files")}:
            return False
        if type(new.get("reference_files")) is not int:  # 969.0 や true は == で一致するが、verify が拒否する
            return False
        return manifest_from_tree(root, head, template) == new
    except (Undecidable, ValueError):
        return False


def _no_duplicates(pairs):
    """同じキーが2度ある記録は、読む道具によって値が変わるので無効にする。"""
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def blocks(bodies, tag):
    found = []
    for body in bodies:
        for name, text in BLOCK.findall(body or ""):
            if name == tag:
                try:
                    found.append(json.loads(text, object_pairs_hook=_no_duplicates))
                except ValueError:
                    continue
    return found


def audit_ok(bodies, head):
    for record in blocks(bodies, AUDIT_TAG):
        if (isinstance(record, dict) and record.get("head") == head and record.get("verdict") == "pass"
                and isinstance(record.get("reviewer"), str) and record["reviewer"].strip()
                and isinstance(record.get("checked"), list) and record["checked"]):
            return record
    return None


def change_subject(repo, head, base_ref):
    return hashlib.sha256(canonical({"repo": repo, "head": head, "base_ref": base_ref})).hexdigest()


def owner_ok(bodies, repo, head, key, base_ref):
    """本人の承認は最新コミットと基準ブランチに結び付くので、期限は見ない。コミットが進めば無効になる。"""
    subject = change_subject(repo, head, base_ref)
    public = (int(key["n"], 16), int(key["e"]))
    import base64
    for grant in blocks(bodies, OWNER_TAG):
        if not isinstance(grant, dict) or grant.get("kind") != OWNER_KIND or grant.get("subject_sha256") != subject:
            continue
        unsigned = {k: v for k, v in grant.items() if k != "signature"}
        try:
            signature = base64.b64decode(grant.get("signature", ""), validate=True)
        except (ValueError, TypeError):
            continue
        if rsa_verify(public, GRANT_PREFIX + canonical(unsigned), signature):
            return grant
    return None


def evaluate(root, base, head, bodies, repo, base_ref, default_branch):
    if base_ref != default_branch:
        # 既定ブランチ以外を基準にしたPRは判定しない。細工した基準で空の差分や別の差分を作り、通過を得る経路を塞ぐ。
        raise Undecidable(f"基準ブランチが既定ブランチ（{default_branch}）でない：{base_ref}")
    try:
        policy, found = read_policy(root, base)
    except (Undecidable, ValueError):
        raise Undecidable("基準側の段の表を読めない")
    items = changes(root, base, head)
    tier, files, reasons = classify(items, policy)
    derived = tier != "T0" and derived_manifest_ok(root, base, head, items, policy)
    if derived:
        tier, reasons = "T0", reasons + ["目録だけの変更で、head の木から作り直した物と一致する（T0）"]
        files = {path: "T0" for path in files}
    result = {"tier": tier, "head": head, "base": base, "reasons": reasons, "derived_manifest": derived,
              "files": {t: sorted(p for p, v in files.items() if v == t) for t in policy["order"]}}
    if tier == "T0":
        result.update(ok=True, needs="CIが緑")
    elif tier == "T1":
        record = audit_ok(bodies, head)
        result.update(ok=record is not None, needs="最新コミットへの独立監査の記録",
                      evidence=record and {k: record.get(k) for k in ("reviewer", "verdict")})
    else:
        try:
            key = json.loads(git(root, "show", f"{base}:{found[1]}"))
        except (Undecidable, ValueError):
            raise Undecidable("基準側の本人の公開鍵を読めない")
        grant = owner_ok(bodies, repo, head, key, base_ref)
        result.update(ok=grant is not None, needs="最新コミットへの本人の署名つき承認",
                      evidence=grant and {"owner_note": grant.get("owner_note"), "issued_at": grant.get("issued_at")})
    return result


def api(url, token, data=None, method=None):
    request = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                     headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                                              "User-Agent": "asteria-delivery-gate"},
                                     method=method or ("POST" if data is not None else "GET"))
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


TRUSTED_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}


def pr_comments(repo, pr, token):
    """リポジトリの持ち主・協力者が書いたコメントだけを証拠として読む。"""
    bodies, page = [], 1
    while True:
        batch = api(f"https://api.github.com/repos/{repo}/issues/{pr}/comments?per_page=100&page={page}", token)
        bodies += [c.get("body", "") for c in batch if c.get("author_association") in TRUSTED_ASSOCIATIONS]
        if len(batch) < 100:
            return bodies
        page += 1


def fetch_pr(root, pr):
    """PRの最新コミットを手元へ取得する（実行はしない）。"""
    git(root, "fetch", "--no-tags", "origin", f"pull/{pr}/head")


def judge(root, repo, pr, token, info, default, base=None):
    """コミットの状態の表示は信じず、手元で関門の判定をやり直す。

    状態（statuses）は、PRの枝に置いたワークフローからでもCIのボット名義で書けるため、マージの根拠にしない。
    段の表・鍵・検査器は手元の基準側の版（git show <基準>:…）で読む。
    """
    fetch_pr(root, pr)
    return evaluate(root, base or info["base"]["sha"], info["head"]["sha"], pr_comments(repo, pr, token), repo,
                    info["base"]["ref"], default)


def required_checks(root, base):
    try:
        return read_policy(root, base)[0].get("required_checks", [])
    except (Undecidable, ValueError):
        raise Undecidable("基準側の段の表を読めない")


def merge(root, repo, pr, token):
    """関門の判定を手元でやり直し、通った時だけ、確かめた最新コミットを固定してマージする。"""
    check_origin(root, repo)
    info = api(f"https://api.github.com/repos/{repo}/pulls/{pr}", token)
    default = api(f"https://api.github.com/repos/{repo}", token)["default_branch"]
    head = info["head"]["sha"]
    problems = []
    if info.get("state") != "open" or info.get("draft"):
        problems.append("開いていない、または下書き")
    if info["base"]["ref"] != default:
        problems.append(f"基準が既定ブランチでない（{info['base']['ref']}）")
    if not problems:
        tip = default_tip(root, default)  # 判定の基準は、今の既定ブランチの先端（マージ先）
        verdict = judge(root, repo, pr, token, info, default, tip)
        if not verdict["ok"]:
            problems.append(f"関門：{verdict['tier']} の証拠が無い（{verdict['needs']}）")
        elif verdict.get("derived_manifest") and not watch(root, repo, token)["ok"]:
            # 目録の例外は「main が関門を通った中身だけ」が前提。直接のpushがあれば、目録で正当化させない
            problems.append("事後照合に違反があるため、目録だけのPRをマージしない")
        runs = api(f"https://api.github.com/repos/{repo}/commits/{head}/check-runs?per_page=100", token)["check_runs"]
        done = {run.get("name"): run.get("conclusion") for run in runs}
        for name in required_checks(root, tip):
            if done.get(name) != "success":
                problems.append(f"必須のCI {name} が成功していない（{done.get(name)}）")
        if any(c not in ("success", "skipped", "neutral") for n, c in done.items() if n != "gate"):
            problems.append("成功していないCIがある")
    if problems:
        return {"ok": False, "pr": pr, "head": head, "problems": problems}
    done = api(f"https://api.github.com/repos/{repo}/pulls/{pr}/merge", token, {"sha": head, "merge_method": "merge"},
               method="PUT")
    return {"ok": bool(done.get("merged")), "pr": pr, "head": head, "merge_commit": done.get("sha")}


def data_update_paths(root, sha):
    """そのコミットが、親1つの直接の変更で、親の版の段の表の data_paths に列挙されたパスだけを
    状態M・モード不変で変えた物なら、その変更したパスの一覧を返す。それ以外（マージ、追加・削除・改名・
    特殊なモード・モード変更（例：100644→100755）・列挙外のパス、data_paths の無いリポジトリ）は
    None（＝例外を使わず、今までどおり違反として扱う）。data_paths は段の表（T2）で足すので、
    ここも基準側＝親の版で読む。モードまで直接見る（changes() の special は symlink/submodule しか見ないため）。

    data_paths の照合はGitのパスと完全一致（大文字小文字も区別する。段の分類＝tier_of が大文字小文字を
    無視するのとは別）。data_paths 自身に、その段の表に照らしてT2になるパス（段の表自身・鍵・
    .asteria/**・.github/**・.claude/** など）が1つでも入っていたら、data_paths は丸ごと無効にする
    （段の表を使って自分自身の保護を外す経路を塞ぐ。2026-10-03 Astraの指摘）。
    """
    parents = git(root, "rev-list", "--parents", "-n", "1", sha).split()[1:]
    if len(parents) != 1:
        return None
    try:
        policy = read_policy(root, parents[0])[0]
    except Undecidable:
        return None
    raw_paths = policy.get("data_paths", [])
    if not raw_paths or any(tier_of(p, policy) == "T2" for p in raw_paths):
        return None
    data_paths = set(raw_paths)
    fields = git(root, "diff", "--raw", "-z", "-M", f"{parents[0]}...{sha}").split("\0")
    changed, i = [], 0
    while i < len(fields):
        meta = fields[i].split()
        if len(meta) < 5 or not meta[0].startswith(":"):
            i += 1
            continue
        old_mode, new_mode, state = meta[0][1:], meta[1], meta[4][0]
        count = 2 if state in "RC" else 1
        paths = fields[i + 1:i + 1 + count]
        i += 1 + count
        if state != "M" or old_mode != new_mode or old_mode in SPECIAL_MODES or new_mode in SPECIAL_MODES:
            return None
        if paths[0] not in data_paths:
            return None
        changed.append(paths[0])
    return changed or None


def watch(root, repo, token):
    """既定ブランチの第一親の履歴を、照合の起点から全部たどる。各コミットは、既定ブランチへ入ったPRのマージで、
    手元でやり直した関門の判定が通っていなければならない。それ以外（直接のpush、手元でのmergeのpush、
    関門を通っていないマージ）と、起点が履歴から消えた（force-push）事を違反にする。日時では絞らない。
    例外：親1つの直接のコミットが data_paths に列挙されたパスだけを変えた物は、違反でなく data_updates に残す
    （段の表を data_paths で弱めるPR自体はT2で本人の署名が要るので、ここでは件数と最新のshaだけ残す）。
    """
    check_origin(root, repo)
    default = api(f"https://api.github.com/repos/{repo}", token)["default_branch"]
    tip = default_tip(root, default)
    anchor = required_anchor(root, tip)
    if git_ok(root, "merge-base", "--is-ancestor", anchor, tip) is False:
        return {"ok": False, "violations": [{"kind": "起点が履歴から消えた（force-pushの疑い）", "anchor": anchor}]}
    commits = git(root, "rev-list", "--first-parent", f"{anchor}..{tip}").split()
    violations, introductions, data_updates = [], [], []
    for sha in reversed(commits):
        pulls = [p for p in api(f"https://api.github.com/repos/{repo}/commits/{sha}/pulls", token)
                 if p.get("merged_at") and p["base"]["ref"] == default and p.get("merge_commit_sha") == sha]
        if not pulls:
            if data_update_paths(root, sha) is not None:
                data_updates.append(sha)
                continue
            subject = git(root, "log", "-1", "--format=%s", sha).strip()
            violations.append({"kind": "PRのマージでない変更", "sha": sha, "subject": subject})
            continue
        pull = pulls[0]
        shape = merge_shape(root, sha, pull["head"]["sha"])
        if shape:
            violations.append({"kind": "マージコミットの中身がPRと合わない", "pr": pull["number"], "sha": sha, "detail": shape})
            continue
        try:
            base_layout = layout(root, f"{sha}^1")
        except Undecidable as exc:
            violations.append({"kind": "関門を通っていないマージ", "pr": pull["number"], "sha": sha, "detail": str(exc)})
            continue
        if base_layout is None:
            # 関門を入れたマージ自体。基準側に段の表が無いので判定できない。違反にせず、導入として報告に残す。
            # ただし、それより前の第一親の履歴に段の表が一度でもあった（消してから足し直した）なら、再導入として違反。
            earlier = git(root, "log", "--first-parent", "-1", "--format=%H", f"{sha}^1", "--",
                          *[policy for policy, _ in LAYOUTS]).strip()
            if earlier:
                violations.append({"kind": "段の表を消してから足し直したマージ（再導入）", "pr": pull["number"], "sha": sha,
                                   "earlier": earlier})
            else:
                introductions.append({"pr": pull["number"], "sha": sha, "title": pull["title"]})
            continue
        try:
            verdict = judge(root, repo, pull["number"], token, pull, default, f"{sha}^1")
            ok = verdict["ok"]
        except (Undecidable, OSError, ValueError, KeyError, TypeError) as exc:
            ok, verdict = False, {"error": f"判定できない：{exc}"}
        if not ok:
            violations.append({"kind": "関門を通っていないマージ", "pr": pull["number"], "title": pull["title"],
                               "sha": sha, "detail": verdict.get("needs") or verdict.get("error")})
    return {"ok": not violations, "anchor": anchor, "checked": len(commits), "violations": violations,
            "introductions": introductions,
            "data_updates": {"count": len(data_updates), "latest": data_updates[-1] if data_updates else None}}


def check_origin(root, repo):
    """手元の作業木が、そのリポジトリの物であること。別のリポジトリのPRを、この作業木の表で判定しない。"""
    url = git(root, "remote", "get-url", "origin").strip().removesuffix(".git").rstrip("/")
    if not url.lower().endswith("/" + repo.lower()) and not url.lower().endswith(":" + repo.lower()):
        raise Undecidable(f"手元の作業木（{url}）が {repo} でない。そのリポジトリの作業木で実行する")


def merge_shape(root, sha, head):
    """PRのマージは、第一親＝既定ブランチ、第二親＝PRの最新コミットで、木がその2つの機械的なマージと一致すること。
    手元で中身を書き換えたマージ（evil merge）や、つぶしたマージを、PRのマージとして通さない。"""
    parents = git(root, "rev-list", "--parents", "-n", "1", sha).split()[1:]
    if len(parents) != 2:
        return f"親が{len(parents)}個（PRの通常のマージでない）"
    if parents[1] != head:
        return "第二親がPRの最新コミットでない"
    run = subprocess.run(["git", "merge-tree", "--write-tree", parents[0], parents[1]], cwd=root,
                         capture_output=True, text=True)
    if run.returncode != 0:
        return "機械的なマージで競合が出る（手で解いたマージ）"
    if run.stdout.split()[0] != git(root, "rev-parse", f"{sha}^{{tree}}").strip():
        return "木が機械的なマージと違う（マージで中身を書き換えた）"
    return None


def default_tip(root, default):
    git(root, "fetch", "--no-tags", "origin", default)
    return git(root, "rev-parse", "FETCH_HEAD").strip()


def git_ok(root, *args):
    run = subprocess.run(["git", *args], cwd=root, capture_output=True)
    return run.returncode == 0


def required_anchor(root, tip):
    """照合の起点は、段の表に watch_from が最初に記録された版の値で固定する。導入の版に watch_from が
    無ければ、その後の第一親の履歴を進んで、最初に記録された版まで見る（asteriaの実例：関門の立ち上げ期の
    マージを飛ばすため、導入より後のコミットで初めて watch_from を記録した）。どの版にも無ければ導入コミット
    自身を起点にする。後から watch_from を書き換えても見ない（起点を前へ動かせなくする。2026-10-03
    Astraの指摘：直接コミットで段の表を改ざんし、次のコミットで watch_from をそのコミットより後ろへ動かして
    照合範囲外にする経路を塞ぐ）。記録された値は、それを記録したコミットの祖先か同じでなければ無効
    （起点を自分より先へ置けない）。"""
    history = git(root, "rev-list", "--first-parent", "--reverse", tip).split()
    introduction = next((sha for sha in history if layout(root, sha)), None)
    if introduction is None:
        raise Undecidable("段の表がどこにも無い")
    for sha in history[history.index(introduction):]:
        if not layout(root, sha):  # 表を消して足し直した間の版（再導入は watch() が別に違反にする）
            continue
        try:
            policy = read_policy(root, sha)[0]
        except Undecidable:
            raise Undecidable(f"段の表を読めない：{sha}")
        if "watch_from" not in policy:
            continue
        anchor = policy["watch_from"]
        if not isinstance(anchor, str) or not re.fullmatch(r"[0-9a-f]{40}", anchor):  # 空・null も形が違う
            raise Undecidable("照合の起点の形が違う")
        if git_ok(root, "merge-base", "--is-ancestor", anchor, sha) is False:
            raise Undecidable("照合の起点が、それを記録したコミットの祖先でない（起点を自分より先へ置けない）")
        return anchor
    return introduction


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".")
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--pr")
    parser.add_argument("--base-ref", help="PRの基準ブランチ名")
    parser.add_argument("--default-branch")
    parser.add_argument("--comments", help="コメント本文の配列のJSONファイル（試験・手元用）")
    parser.add_argument("--post-status", action="store_true")
    parser.add_argument("--merge", metavar="PR", help="関門が通したPRだけをマージする（AIがマージする唯一の経路）")
    parser.add_argument("--watch", action="store_true", help="既定ブランチの照合の起点からの全マージを照合する")
    args = parser.parse_args(argv)
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:  # delivery_integrate.py と同じやり方。AIがシェルで `gh auth token` を打たなくて済むように
        try:
            token = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            token = ""
    if args.merge or args.watch:
        if not token or not args.repo:
            print(json.dumps({"ok": False, "error": "GITHUB_TOKEN と --repo が要る"}, ensure_ascii=False))
            return 2
        try:
            result = merge(args.root, args.repo, args.merge, token) if args.merge else watch(args.root, args.repo, token)
        except (Undecidable, OSError, ValueError, KeyError, TypeError) as exc:
            print(json.dumps({"ok": False, "error": f"判定できない：{exc}"}, ensure_ascii=False))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=1))
        return 0 if result["ok"] else 1
    if not (args.base and args.head and args.base_ref and args.default_branch):
        parser.error("--base・--head・--base-ref・--default-branch が要る")
    try:
        if args.comments:
            bodies = json.loads(Path(args.comments).read_text(encoding="utf-8"))
        elif args.pr and token:
            bodies = pr_comments(args.repo, args.pr, token)
        else:
            bodies = []
        result = evaluate(args.root, args.base, args.head, bodies, args.repo, args.base_ref, args.default_branch)
        code = 0 if result["ok"] else 1
    except (Undecidable, OSError, ValueError, KeyError, TypeError) as exc:
        result, code = {"ok": False, "error": f"判定できない：{exc}"}, 2
    print(json.dumps(result, ensure_ascii=False, indent=1))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write(f"### 配送の関門：{result.get('tier', '?')} → {'通過' if code == 0 else '保留'}\n\n"
                      f"{result.get('needs') or result.get('error')}\n")
    if args.post_status and token and args.repo:
        state = "success" if code == 0 else "failure" if code == 1 else "error"
        text = f"{result.get('tier', '?')}: " + ("通過" if code == 0 else result.get("needs") or result.get("error", ""))
        try:
            api(f"https://api.github.com/repos/{args.repo}/statuses/{args.head}", token,
                {"state": state, "context": STATUS_CONTEXT, "description": text[:140]})
        except OSError:
            print("状態を付けられなかった", file=sys.stderr)
            return 3
    return code


if __name__ == "__main__":
    sys.exit(main())
