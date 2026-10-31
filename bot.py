"""Telegram bot: send it a link (or a message containing one) and get a risk report back."""
import asyncio
import base64
import io
import os
import re

from dotenv import load_dotenv

load_dotenv()

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

from scanner import format_report, scan

URL_RE = re.compile(r"(https?://\S+|(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?:/\S*)?)", re.I)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 Send me any suspicious link (or forward the whole SMS/message).\n"
        "I'll check if it's known to be malicious, open it safely in an isolated sandbox, "
        "and tell you what it's after and how likely it's a scam.")


async def handle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or update.message.caption or "")
    for ent in (update.message.entities or []):          # Telegram-detected links first
        if ent.type == "text_link" and ent.url:
            text = ent.url + " " + text
    m = URL_RE.search(text)
    if not m:
        await update.message.reply_text("Send me a link to check 🔗")
        return
    url = re.sub(r"\d{1,2}:\d{2}$", "", m.group(0)).rstrip(".,;:!?)")

    status = await update.message.reply_text("⏳ Got it — scanning, this takes ~20-60s...")
    loop = asyncio.get_running_loop()

    def progress(msg):
        asyncio.run_coroutine_threadsafe(status.edit_text(msg), loop)

    try:
        report = await asyncio.to_thread(scan, url, progress)
    except Exception as e:
        await status.edit_text(f"❌ Scan failed: {e}"[:500])
        return

    try:
        await status.delete()
    except Exception:
        pass
    if report.get("screenshot_b64"):
        img = io.BytesIO(base64.b64decode(report["screenshot_b64"]))
        img.name = "page.jpg"
        await update.message.reply_photo(
            photo=img, caption=f"📸 What the page looks like (opened safely in the sandbox)\n"
                               f"{report['verdict']} — {report['score']}/100")
    await update.message.reply_text(format_report(report), disable_web_page_preview=True)


def main():
    app = Application.builder().token(os.environ["TELEGRAM_BOT_TOKEN"]).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle))
    print("Bot running. Send it a link on Telegram. Ctrl+C to stop.")
    app.run_polling()


if __name__ == "__main__":
    main()