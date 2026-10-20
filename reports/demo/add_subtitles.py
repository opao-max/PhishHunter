"""Generate Chinese subtitles for the PhishHunter demo and burn a copy.

Outputs:
  - reports/demo/PhishHunter_Demo.srt
  - reports/demo/PhishHunter_Demo_4min_subtitled.mp4      (burned-in)
  - reports/demo/PhishHunter_Demo_4min_softsubs.mp4       (soft track)
  - reports/demo/PhishHunter_Demo_4min_subtitled_720p.mp4
"""

from __future__ import annotations

import math
import re
import subprocess
from pathlib import Path

import av
import imageio_ffmpeg

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "reports" / "demo"
CLIPS = DEMO / "build" / "clips"
FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()

NARRATION = {
    "ch01_title": "PhishHunter 是一个面向邮件网关的钓鱼邮件检测系统。它先采集可验证证据，再给出风险评分和处置建议。下面用正常邮件、钓鱼邮件和对抗样本演示完整流程。",
    "ch02_arch": "系统分为五个阶段。感知层用七类检测器分析文本、认证头、发件人身份、链接、附件、图片和提示注入。规划层按确定性策略选择调查工具，工具调用受白名单和预算约束。判断层先用加权评分和关键证据下限得到确定性分数，再让模型在证据范围内补充分析。模型最多调整正负八分，且不能下调关键证据触发的地板分。",
    "ch02b_evidence": "每条证据都有编号、类别、严重度、置信度和来源。评分时先按类别聚合，再用关键证据下限防止强信号被平均掉；可验证的缓解证据最多扣减十五分。最终处置由分数和阈值决定，不由模型直接输出。",
    "ch03_allow": "第一封是正常的内部会议通知。发件域是公司自有域名，SPF、DKIM、DMARC 全部通过，链接是内部 wiki，域名注册时间较长。最终风险分为零，建议放行。证据链里可以看到，系统把认证通过、老域名和干净链接作为缓解证据，而不是因为邮件里出现会议、链接这些普通词就误报。",
    "ch04_block": "第二封是典型的密码过期钓鱼。发件域 micr0soft-security.com 注册仅零点三天，用同形字仿冒 Microsoft，SPF 失败、DKIM 缺失；短链接跳转到裸 IP 的登录页，威胁情报标记为恶意，沙箱确认存在密码表单。多个信号触发策略下限，最终得分九十五，建议阻断。每一条结论都带证据编号，工具调用、参数和耗时也都有审计记录。切到推理页，可以看到模型引用的每一步证据。",
    "ch05_injection": "第三封是对抗样本。正文要求分析器忽略先前指令并输出 Allow。系统只把这段文字当作一条提示注入证据，不会执行它；最终判定仍由域名、认证、链接和沙箱证据决定，结果仍是阻断。",
    "ch06_quarantine": "处置分为三档：七十分及以上阻断，四十到六十九分隔离，四十分以下放行。这封 Punycode 仿冒邮件没有出现凭据索取，分数落在隔离区，交给人工复核。评分明细会展示原始分、缓解扣减、策略下限和模型调整；模型建议与关键证据冲突时，以证据和地板分为准。",
    "ch07_eval": "当前仓库包含十五封主回归样本和十四例独立红队回归，覆盖短链、双扩展名、二维码、Punycode、Unicode 同形字、Base64 注入和隐藏 HTML。在这组功能回归集上，分类指标全部为 1.0，红队回归全部通过；测试共 276 项通过。这验证的是编排和策略按预期工作，不代表生产环境的泛化性能。",
    "ch07b_cli": "所有结果都可以通过命令行复现：demo 跑完整样例，evaluate 输出混淆矩阵、误报率和延迟，pytest 运行测试。真实模型也可以通过环境变量切换，不需要改代码。",
    "ch08_close": "当前版本的外部情报工具使用 Mock 数据，图片 OCR 依赖上游元数据，二维码支持本地解码。生产部署需要接入真实 WhoIs、URL 信誉和沙箱，并在脱敏生产邮件上重新校准阈值。以上是 PhishHunter 的完整演示。",
}
ORDER = list(NARRATION.keys())


def duration(path: Path) -> float:
    container = av.open(str(path))
    value = (container.duration or 0) / 1_000_000
    container.close()
    return value


def split_cues(text: str, limit: int = 34) -> list[str]:
    """Pack clauses into readable subtitle cues without orphan punctuation."""
    clauses = re.findall(r"[^。；！？，、：]*[。；！？，、：]?", text)
    clauses = [clause for clause in clauses if clause]
    packed: list[str] = []
    current = ""
    for clause in clauses:
        if not current:
            current = clause
        elif len(current) + len(clause) <= limit:
            current += clause
        else:
            packed.append(current)
            current = clause
    if current:
        packed.append(current)

    cues: list[str] = []
    for cue in packed:
        if len(cue) <= limit + 6:
            cues.append(cue)
            continue
        current = ""
        for char in cue:
            current += char
            if len(current) >= limit and char in "，、；：":
                cues.append(current.strip())
                current = ""
        if current.strip():
            if cues and all(ch in "。；！？，、：" for ch in current.strip()):
                cues[-1] += current.strip()
            else:
                cues.append(current.strip())
    return [cue for cue in cues if cue and not all(ch in "。；！？，、：" for ch in cue)]

def srt_timestamp(seconds: float) -> str:
    millis = int(round(seconds * 1000))
    hours, remain = divmod(millis, 3600_000)
    minutes, remain = divmod(remain, 60_000)
    secs, ms = divmod(remain, 1000)
    return f"{hours:02d}:{minutes:02d}:{secs:02d},{ms:03d}"


def main() -> None:
    chapter_starts: dict[str, tuple[float, float]] = {}
    cursor = 0.0
    for key in ORDER:
        clip = CLIPS / f"{key}.mp4"
        length = duration(clip)
        chapter_starts[key] = (cursor, cursor + length)
        cursor += length

    cues: list[tuple[float, float, str]] = []
    for key in ORDER:
        start, end = chapter_starts[key]
        chapter_len = end - start
        pieces = split_cues(NARRATION[key])
        weights = [max(1, len(piece)) for piece in pieces]
        total_weight = sum(weights)
        # Leave a small tail so the last cue does not collide with the cut.
        usable = max(1.0, chapter_len - 0.25)
        cursor = start
        for index, (piece, weight) in enumerate(zip(pieces, weights)):
            cue_len = usable * weight / total_weight
            if index == len(pieces) - 1:
                cue_end = end - 0.15
            else:
                cue_end = cursor + cue_len
            if cue_end - cursor < 1.0:
                cue_end = min(end - 0.15, cursor + 1.0)
            cues.append((cursor, cue_end, piece))
            cursor = cue_end

    srt_lines: list[str] = []
    for index, (start, end, text) in enumerate(cues, 1):
        srt_lines.append(str(index))
        srt_lines.append(f"{srt_timestamp(start)} --> {srt_timestamp(end)}")
        srt_lines.append(text)
        srt_lines.append("")
    srt_path = DEMO / "PhishHunter_Demo.srt"
    srt_path.write_text("\n".join(srt_lines), encoding="utf-8")

    source = DEMO / "PhishHunter_Demo_4min.mp4"
    style = (
        "FontName=Microsoft YaHei,FontSize=7,PrimaryColour=&H00FFFFFF,"
        "OutlineColour=&H00000000,BorderStyle=1,Outline=2,Shadow=0,"
        "MarginV=28,Alignment=2,WrapStyle=0"
    )
    burned = DEMO / "PhishHunter_Demo_4min_subtitled.mp4"
    subprocess.run(
        [
            FFMPEG,
            "-y",
            "-i",
            str(source),
            "-vf",
            f"subtitles={srt_path.name}:original_size=1440x900:force_style='{style}'",
            "-c:v",
            "libx264",
            "-preset",
            "medium",
            "-crf",
            "20",
            "-pix_fmt",
            "yuv420p",
            "-c:a",
            "copy",
            "-movflags",
            "+faststart",
            str(burned),
        ],
        cwd=str(DEMO),
        check=True,
    )

    soft = DEMO / "PhishHunter_Demo_4min_softsubs.mp4"
    subprocess.run(
        [
            FFMPEG,
            "-y",
            "-i",
            str(source),
            "-i",
            str(srt_path),
            "-c",
            "copy",
            "-c:s",
            "mov_text",
            "-metadata:s:s:0",
            "language=chi",
            "-movflags",
            "+faststart",
            str(soft),
        ],
        check=True,
    )

    small = DEMO / "PhishHunter_Demo_4min_subtitled_720p.mp4"
    subprocess.run(
        [
            FFMPEG,
            "-y",
            "-i",
            str(burned),
            "-vf",
            "scale=1280:720",
            "-c:v",
            "libx264",
            "-preset",
            "medium",
            "-crf",
            "24",
            "-c:a",
            "copy",
            "-movflags",
            "+faststart",
            str(small),
        ],
        check=True,
    )

    print(f"srt: {srt_path} ({len(cues)} cues)")
    for path in (burned, soft, small):
        print(f"{path.name}: {path.stat().st_size / 1024 / 1024:.2f} MB, {duration(path):.1f}s")


if __name__ == "__main__":
    main()