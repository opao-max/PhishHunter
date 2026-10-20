"""Build the PhishHunter 4-minute narrated demo video.

Inputs:
  - reports/demo/build/audio/*.mp3   (generated with Edge TTS, Yunyang)
  - running PhishHunter web server on 127.0.0.1:8765
Outputs:
  - reports/demo/PhishHunter_Demo_4min.mp4
  - reports/demo/PhishHunter_Demo_4min_720p.mp4
  - reports/demo/NARRATION.md

This script is a build artifact, not part of the runtime package.
"""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
from pathlib import Path

import av
import imageio_ffmpeg
from PIL import Image, ImageDraw, ImageFont
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "reports" / "demo"
BUILD = DEMO / "build"
AUDIO = BUILD / "audio"
SLIDES = BUILD / "slides"
RAW = BUILD / "raw"
CLIPS = BUILD / "clips"
for directory in (SLIDES, RAW, CLIPS):
    directory.mkdir(parents=True, exist_ok=True)

FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()
W, H, FPS = 1440, 900, 25

FONT_REG = r"C:\Windows\Fonts\msyh.ttc"
FONT_BOLD = r"C:\Windows\Fonts\msyhbd.ttc"


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    path = FONT_BOLD if bold and os.path.exists(FONT_BOLD) else FONT_REG
    return ImageFont.truetype(path, size)


def text_width(draw: ImageDraw.ImageDraw, text: str, fnt: ImageFont.FreeTypeFont) -> int:
    box = draw.textbbox((0, 0), text, font=fnt)
    return box[2] - box[0]


def wrap(draw: ImageDraw.ImageDraw, text: str, fnt: ImageFont.FreeTypeFont, width: int) -> list[str]:
    lines: list[str] = []
    current = ""
    for char in text:
        if char == "\n":
            lines.append(current)
            current = ""
            continue
        candidate = current + char
        if text_width(draw, candidate, fnt) <= width:
            current = candidate
        else:
            lines.append(current)
            current = char
    if current:
        lines.append(current)
    return lines


def canvas() -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (W, H), "#ffffff")
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, W - 1, H - 1), outline="#d0d0d0", width=1)
    draw.text((70, 34), "PhishHunter 钓鱼邮件检测系统", font=font(17), fill="#666666")
    draw.line((70, 66, W - 70, 66), fill="#d9d9d9", width=1)
    return image, draw


def footer(draw: ImageDraw.ImageDraw, page: int) -> None:
    draw.text((70, H - 44), "PhishHunter 1.0 · 演示视频", font=font(14), fill="#888888")
    draw.text((W - 110, H - 44), f"{page:02d}", font=font(14), fill="#888888")


def title_slide() -> Image.Image:
    image, draw = canvas()
    draw.text((70, 210), "PhishHunter", font=font(64, True), fill="#111111")
    draw.text((70, 300), "钓鱼邮件检测系统", font=font(46, True), fill="#111111")
    draw.line((72, 390, 620, 390), fill="#333333", width=2)
    draw.text((70, 425), "证据驱动的钓鱼邮件分析与处置建议", font=font(25), fill="#444444")
    draw.text((70, 500), "2027 届交大捷普秋季校园招聘 AI 试题", font=font(19), fill="#666666")
    draw.text((70, 540), "演示内容：架构 · 正常邮件 · 钓鱼邮件 · 对抗样本 · 评估", font=font(19), fill="#666666")
    footer(draw, 1)
    return image


def architecture_slide() -> Image.Image:
    image, draw = canvas()
    draw.text((70, 100), "系统架构：五个阶段", font=font(38, True), fill="#111111")
    draw.text((70, 155), "Perceive → Plan → Act → Judge → Report", font=font(19), fill="#666666")

    labels = [
        ("感知", "Perceive", "七类静态检测器"),
        ("规划", "Plan", "确定性策略 + 白名单"),
        ("行动", "Act", "WhoIs / URL / 沙箱 / 文件"),
        ("判断", "Judge", "证据评分 + 关键下限"),
        ("报告", "Report", "评分 / 证据链 / 建议"),
    ]
    box_w, box_h, gap, top = 215, 118, 39, 240
    for index, (cn, en, detail) in enumerate(labels):
        x = 70 + index * (box_w + gap)
        draw.rectangle((x, top, x + box_w, top + box_h), outline="#333333", width=2, fill="#ffffff")
        draw.text((x + 16, top + 16), cn, font=font(24, True), fill="#111111")
        draw.text((x + 16, top + 52), en, font=font(16), fill="#666666")
        draw.text((x + 16, top + 82), detail, font=font(13), fill="#777777")
        if index < len(labels) - 1:
            ax = x + box_w
            draw.line((ax + 6, top + box_h // 2, ax + gap - 8, top + box_h // 2), fill="#555555", width=2)
            draw.polygon(
                [
                    (ax + gap - 8, top + box_h // 2),
                    (ax + gap - 18, top + box_h // 2 - 5),
                    (ax + gap - 18, top + box_h // 2 + 5),
                ],
                fill="#555555",
            )

    draw.text((70, 430), "证据链", font=font(22, True), fill="#111111")
    chain = "静态证据 + 工具证据 → 去重编号 → 加权评分 → 关键证据下限 → 受限模型 ±8 → 处置建议"
    draw.text((70, 468), chain, font=font(17), fill="#444444")
    draw.text((70, 525), "确定性检测器", font=font(18), fill="#333333")
    draw.text((300, 525), "工具白名单与预算", font=font(18), fill="#333333")
    draw.text((570, 525), "可追溯证据 ID", font=font(18), fill="#333333")
    draw.text((810, 525), "模型只做有界调整", font=font(18), fill="#333333")
    draw.line((70, 585, W - 70, 585), fill="#e0e0e0", width=1)
    draw.text((70, 612), "关键原则：LLM 不能创建证据，只能引用证据；关键证据触发的地板分不可被模型下调。", font=font(18), fill="#444444")
    footer(draw, 2)
    return image


def evidence_slide() -> Image.Image:
    image, draw = canvas()
    draw.text((70, 100), "证据模型与评分", font=font(38, True), fill="#111111")
    draw.text((70, 155), "每一条结论都能追溯到证据编号", font=font(19), fill="#666666")

    draw.rectangle((70, 220, 680, 590), outline="#d0d0d0", width=1)
    draw.text((95, 242), "示例证据", font=font(19, True), fill="#111111")
    mono = ImageFont.truetype(r"C:\Windows\Fonts\simsun.ttc", 17)
    lines = [
        "E006  威胁情报  新注册域名",
        "severity    0.95",
        "confidence  0.95",
        "tags        domain_new",
        "source      tool:whois_lookup",
        "",
        "detail:",
        "域名 micr0soft-security.com",
        "注册仅 0.3 天，属于典型的",
        "钓鱼基础设施特征。",
    ]
    y = 285
    for line in lines:
        draw.text((95, y), line, font=mono, fill="#333333")
        y += 27

    bullets = [
        "每条证据包含编号、类别、严重度、置信度、来源和标签。",
        "类别内使用 noisy-OR 聚合，类别间按权重求和。",
        "关键证据触发策略下限：恶意 URL 95、凭据页 88、双扩展名 85。",
        "可验证的缓解证据最多扣减 15 分。",
        "模型只能在确定性分数上调整 ±8，且不能下调地板分。",
        "最终处置由分数和阈值决定，不由模型直接输出。",
    ]
    y = 225
    for bullet in bullets:
        draw.rectangle((730, y + 8, 738, y + 16), fill="#333333")
        for line in wrap(draw, bullet, font(18), 570):
            draw.text((752, y), line, font=font(18), fill="#333333")
            y += 30
        y += 12
    footer(draw, 3)
    return image


def evaluation_slide() -> Image.Image:
    image, draw = canvas()
    draw.text((70, 100), "评估与测试", font=font(38, True), fill="#111111")
    draw.text((70, 155), "功能回归集与红队回归，不代表生产泛化性能", font=font(19), fill="#666666")
    rows = [
        ("主回归集", "15 封（10 恶意 / 5 正常）"),
        ("Accuracy / Precision / Recall / F1", "1.00 / 1.00 / 1.00 / 1.00"),
        ("FPR / FNR", "0.00 / 0.00"),
        ("独立红队回归", "14 / 14 通过"),
        ("测试", "276 passed, 5 skipped"),
        ("延迟", "中位约 4–6 ms；P95 含二维码冷启动"),
    ]
    top, row_h = 225, 62
    for index, (label, value) in enumerate(rows):
        y = top + index * row_h
        draw.line((70, y, W - 70, y), fill="#e0e0e0", width=1)
        draw.text((85, y + 17), label, font=font(18), fill="#555555")
        draw.text((690, y + 17), value, font=font(19, True), fill="#111111")
    draw.line((70, top + len(rows) * row_h, W - 70, top + len(rows) * row_h), fill="#e0e0e0", width=1)
    draw.text((70, 650), "样本覆盖：密码过期、CEO 转账、双扩展名附件、二维码、短链→IP、Punycode、", font=font(17), fill="#666666")
    draw.text((70, 682), "Unicode 同形字、Base64 注入、隐藏 HTML、伪造工具结果、合法对照。", font=font(17), fill="#666666")
    footer(draw, 4)
    return image


def cli_slide() -> Image.Image:
    image, draw = canvas()
    draw.text((70, 100), "命令行复现", font=font(38, True), fill="#111111")
    draw.text((70, 155), "无需改代码即可复现分析、评估与测试", font=font(19), fill="#666666")
    draw.rectangle((70, 220, W - 70, 545), outline="#d0d0d0", width=1, fill="#fafafa")
    mono = ImageFont.truetype(r"C:\Windows\Fonts\consola.ttf", 20)
    commands = [
        "python -m phishhunter.cli demo",
        "python -m phishhunter.cli analyze data/emails/email_001.json",
        "python -m phishhunter.cli analyze data/emails/email_001.json --json",
        "python -m phishhunter.cli evaluate",
        "python -m pytest -q",
    ]
    y = 255
    for command in commands:
        draw.text((100, y), "$ " + command, font=mono, fill="#222222")
        y += 52
    draw.text((70, 590), "真实模型切换：", font=font(20, True), fill="#111111")
    draw.text((240, 590), "PHISHHUNTER_LLM_PROVIDER=anthropic|openai", font=mono, fill="#333333")
    draw.text((70, 628), "配置对应 API Key 与模型名即可，编排、证据约束和策略层保持不变。", font=font(18), fill="#555555")
    footer(draw, 5)
    return image


def closing_slide() -> Image.Image:
    image, draw = canvas()
    draw.text((70, 100), "边界与后续工作", font=font(38, True), fill="#111111")
    bullets = [
        "外部情报工具使用 Mock 数据（题目允许）；生产需接入真实 WhoIs、URL 信誉和沙箱。",
        "图片 OCR 依赖上游元数据；二维码支持本地 OpenCV 解码。",
        "当前指标来自 15 封功能回归集，不代表生产环境的泛化性能。",
        "真实模型支持 OpenAI-compatible / Anthropic 接入，API Key 不写入代码。",
        "后续：跨邮件关联、置信度校准、分析师反馈闭环、SOAR 联动。",
    ]
    y = 230
    for bullet in bullets:
        draw.rectangle((72, y + 8, 80, y + 16), fill="#333333")
        for line in wrap(draw, bullet, font(21), 1180):
            draw.text((96, y), line, font=font(21), fill="#333333")
            y += 36
        y += 24
    draw.line((70, 650, W - 70, 650), fill="#d9d9d9", width=1)
    draw.text((70, 680), "谢谢观看", font=font(28, True), fill="#111111")
    footer(draw, 6)
    return image


SLIDE_FACTORIES = {
    "ch01_title": title_slide,
    "ch02_arch": architecture_slide,
    "ch02b_evidence": evidence_slide,
    "ch07_eval": evaluation_slide,
    "ch07b_cli": cli_slide,
    "ch08_close": closing_slide,
}


def audio_duration(path: Path) -> float:
    container = av.open(str(path))
    duration = (container.duration or 0) / 1_000_000
    container.close()
    return duration


def run_ffmpeg(args: list[str]) -> None:
    result = subprocess.run([FFMPEG, "-y", *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        raise RuntimeError(result.stderr[-2000:])


def click_optional(page, selector: str, timeout: int = 2500) -> bool:
    try:
        page.locator(selector).first.click(timeout=timeout)
        return True
    except Exception:
        return False


def record_web(key: str, sample_id: str, mode: str, duration: float) -> Path:
    folder = RAW / key
    folder.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        context = browser.new_context(
            viewport={"width": W, "height": H},
            record_video_dir=str(folder),
            record_video_size={"width": W, "height": H},
        )
        page = context.new_page()
        page.goto("http://127.0.0.1:8765", wait_until="networkidle")
        page.wait_for_function("document.querySelectorAll('#sample-select option').length > 5", timeout=15000)
        page.wait_for_timeout(800)
        page.select_option("#sample-select", sample_id)
        page.click("#analyze-btn")
        page.wait_for_selector("#result:not([hidden])", timeout=20000)
        page.wait_for_timeout(600)

        if mode == "allow":
            page.wait_for_timeout(int(duration * 0.16 * 1000))
            click_optional(page, '.tab[data-tab="evidence"]')
            page.wait_for_timeout(int(duration * 0.15 * 1000))
            click_optional(page, "#evidence-list details summary")
            page.wait_for_timeout(int(duration * 0.16 * 1000))
            click_optional(page, '.tab[data-tab="reasoning"]')
            page.wait_for_timeout(int(duration * 0.16 * 1000))
            click_optional(page, '.tab[data-tab="tools"]')
            page.wait_for_timeout(int(duration * 0.16 * 1000))
            click_optional(page, '.tab[data-tab="overview"]')
        elif mode == "block":
            page.wait_for_timeout(int(duration * 0.12 * 1000))
            click_optional(page, '.tab[data-tab="evidence"]')
            page.wait_for_timeout(int(duration * 0.08 * 1000))
            for title in ("新注册域名", "发件人身份疑似品牌仿冒", "沙箱发现凭据窃取页面"):
                click_optional(page, f'#evidence-list details summary:has-text("{title}")')
                page.wait_for_timeout(int(duration * 0.10 * 1000))
            click_optional(page, '.tab[data-tab="reasoning"]')
            page.wait_for_timeout(int(duration * 0.16 * 1000))
            click_optional(page, '.tab[data-tab="tools"]')
            page.wait_for_timeout(int(duration * 0.14 * 1000))
            click_optional(page, '.tab[data-tab="overview"]')
        elif mode == "injection":
            page.wait_for_timeout(int(duration * 0.24 * 1000))
            click_optional(page, '.tab[data-tab="evidence"]')
            page.wait_for_timeout(int(duration * 0.10 * 1000))
            click_optional(page, '#evidence-list details summary:has-text("提示注入")')
            page.wait_for_timeout(int(duration * 0.34 * 1000))
            click_optional(page, '.tab[data-tab="reasoning"]')
        elif mode == "quarantine":
            page.wait_for_timeout(int(duration * 0.28 * 1000))
            click_optional(page, "#floor-details summary")
            page.wait_for_timeout(int(duration * 0.26 * 1000))
            click_optional(page, '.tab[data-tab="evidence"]')
            page.wait_for_timeout(int(duration * 0.22 * 1000))
            click_optional(page, '.tab[data-tab="overview"]')

        page.wait_for_timeout(max(1200, int(duration * 0.15 * 1000)))
        context.close()
        browser.close()
    files = sorted(glob.glob(str(folder / "*.webm")))
    if not files:
        raise RuntimeError(f"no video recorded for {key}")
    return Path(files[0])


def encode_slide(key: str, image: Image.Image, duration: float) -> Path:
    slide_path = SLIDES / f"{key}.png"
    image.save(slide_path)
    out = CLIPS / f"{key}.mp4"
    run_ffmpeg(
        [
            "-loop", "1", "-i", str(slide_path),
            "-i", str(AUDIO / f"{key}.mp3"),
            "-filter_complex", "[0:v]scale=1440:900,fps=25[v]",
            "-map", "[v]", "-map", "1:a",
            "-c:v", "libx264", "-preset", "medium", "-crf", "20",
            "-pix_fmt", "yuv420p",
            "-c:a", "aac", "-b:a", "160k",
            "-af", "apad=pad_dur=0.3",
            "-t", f"{duration + 0.35:.3f}",
            str(out),
        ]
    )
    return out


def encode_web(key: str, clip: Path, duration: float) -> Path:
    out = CLIPS / f"{key}.mp4"
    run_ffmpeg(
        [
            "-i", str(clip),
            "-i", str(AUDIO / f"{key}.mp3"),
            "-filter_complex",
            "[0:v]scale=1440:900:force_original_aspect_ratio=decrease,"
            "pad=1440:900:(ow-iw)/2:(oh-ih)/2,fps=25,"
            "tpad=stop_mode=clone:stop_duration=600[v]",
            "-map", "[v]", "-map", "1:a",
            "-c:v", "libx264", "-preset", "medium", "-crf", "20",
            "-pix_fmt", "yuv420p",
            "-c:a", "aac", "-b:a", "160k",
            "-af", "apad=pad_dur=0.3",
            "-t", f"{duration + 0.35:.3f}",
            str(out),
        ]
    )
    return out


def main() -> None:
    order = [
        ("ch01_title", "slide", None),
        ("ch02_arch", "slide", None),
        ("ch02b_evidence", "slide", None),
        ("ch03_allow", "web", ("email_007", "allow")),
        ("ch04_block", "web", ("email_001", "block")),
        ("ch05_injection", "web", ("email_012", "injection")),
        ("ch06_quarantine", "web", ("email_015", "quarantine")),
        ("ch07_eval", "slide", None),
        ("ch07b_cli", "slide", None),
        ("ch08_close", "slide", None),
    ]
    narration = ["# PhishHunter 演示视频旁白\n"]
    durations: dict[str, float] = {}
    for key, kind, _data in order:
        audio = AUDIO / f"{key}.mp3"
        if not audio.exists():
            raise FileNotFoundError(audio)
        durations[key] = audio_duration(audio)
        narration.append(f"## {key}\n\n（{durations[key]:.1f} 秒）\n")

    clips: list[Path] = []
    for key, kind, data in order:
        duration = durations[key]
        print(f"[{key}] {duration:.1f}s", flush=True)
        if kind == "slide":
            clip = encode_slide(key, SLIDE_FACTORIES[key](), duration)
        else:
            sample_id, mode = data
            webm = record_web(key, sample_id, mode, duration)
            clip = encode_web(key, webm, duration)
        clips.append(clip)

    concat = BUILD / "concat.txt"
    concat.write_text(
        "\n".join(f"file '{clip.as_posix()}'" for clip in clips),
        encoding="utf-8",
    )
    final = DEMO / "PhishHunter_Demo_4min.mp4"
    run_ffmpeg(
        [
            "-f", "concat", "-safe", "0", "-i", str(concat),
            "-c", "copy", "-movflags", "+faststart", str(final),
        ]
    )
    final_720 = DEMO / "PhishHunter_Demo_4min_720p.mp4"
    run_ffmpeg(
        [
            "-i", str(final),
            "-vf", "scale=1280:720",
            "-c:v", "libx264", "-preset", "medium", "-crf", "24",
            "-c:a", "copy", "-movflags", "+faststart", str(final_720),
        ]
    )
    total = audio_duration(final)
    narration.append(f"\n总时长：{int(total // 60)} 分 {int(total % 60)} 秒\n")
    (DEMO / "NARRATION.md").write_text("\n".join(narration), encoding="utf-8")
    print(f"final: {final} ({final.stat().st_size / 1024 / 1024:.1f} MB, {total:.1f}s)")
    print(f"720p:  {final_720} ({final_720.stat().st_size / 1024 / 1024:.1f} MB)")


if __name__ == "__main__":
    main()