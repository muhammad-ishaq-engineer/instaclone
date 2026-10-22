import os
import json
import uuid
import hmac
import time
import secrets
import threading
from datetime import datetime
from functools import wraps

from flask import Flask, request, redirect, url_for, session, render_template_string, flash, abort, jsonify
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from markupsafe import escape
from db import get_connection as _raw_get_connection

app = Flask(__name__)
_DEFAULT_SECRET = "change-this-development-secret-before-deployment"
app.secret_key = os.environ.get("FLASK_SECRET_KEY", _DEFAULT_SECRET)
if app.secret_key == _DEFAULT_SECRET:
    app.logger.warning("FLASK_SECRET_KEY is not set: using the insecure development secret. Set it before deployment.")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
# 50 MB media + a little multipart form overhead
app.config["MAX_CONTENT_LENGTH"] = 55 * 1024 * 1024
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
VIDEO_EXTENSIONS = {".mp4", ".webm", ".mov"}
MAX_IMAGE_SIZE = 5 * 1024 * 1024
MAX_VIDEO_SIZE = 50 * 1024 * 1024
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ---------------------------------------------------------------------------
# CSRF protection (token lives in the session; JS sends it as X-CSRFToken and
# adds a hidden csrf_token field to every POST form)
# ---------------------------------------------------------------------------
def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(16)
        session["csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = get_csrf_token


def is_ajax():
    return request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json


@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.headers.get("X-CSRFToken") or request.form.get("csrf_token") or ""
        expected = session.get("csrf_token") or ""
        if not expected or not sent or not hmac.compare_digest(str(sent), str(expected)):
            if is_ajax():
                return jsonify(ok=False, message="Your session expired. Please refresh the page and try again."), 400
            abort(400)


PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ title }} | InstaClone</title>
<style>
:root{color-scheme:dark;--bg:#0b0b0d;--panel:#121215;--line:#29292f;--text:#f5f5f7;--muted:#a1a1aa;--blue:#4f9cff;--red:#ff375f}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px Inter,Arial,sans-serif}a{color:inherit;text-decoration:none}button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:0;border-radius:9px;padding:10px 13px;background:var(--blue);color:#fff;cursor:pointer;font:inherit;text-decoration:none;transition:background .15s,transform .15s}button:hover,.btn:hover{filter:brightness(1.08)}button:active{transform:scale(.98)}button:disabled{opacity:.6;cursor:wait}.secondary{background:#29292f;color:var(--text)}input,textarea{width:100%;padding:11px 12px;margin:7px 0 15px;border:1px solid #393941;border-radius:8px;background:#19191e;color:var(--text);font:inherit}textarea{min-height:85px}.app-shell{min-height:100vh}.sidebar{position:fixed;inset:0 auto 0 0;width:238px;border-right:1px solid var(--line);padding:28px 15px;background:#0b0b0d;display:flex;flex-direction:column;z-index:20}.brand{font-size:25px;font-weight:800;letter-spacing:-1px;padding:0 14px 28px}.navlinks{display:grid;gap:7px}.navlink{display:flex;align-items:center;gap:15px;padding:13px 14px;border-radius:10px;color:#eee;transition:background .15s}.navlink:hover,.navlink.active{background:#202025}.navicon{width:23px;text-align:center;font-size:19px}.navbottom{margin-top:auto}.main-area{margin-left:238px;min-height:100vh;padding:26px 30px}.container{max-width:1060px;width:100%;margin:0 auto}.feed-layout{display:grid;grid-template-columns:minmax(0,620px) minmax(220px,290px);gap:38px;justify-content:center;align-items:start}.feed-column{min-width:0}.right-sidebar{position:sticky;top:28px;padding-top:18px}.suggestion-title{display:flex;justify-content:space-between;color:var(--muted);font-weight:700;margin-bottom:18px}.suggestion{display:flex;align-items:center;gap:11px;margin:15px 0}.suggestion-info{min-width:0;flex:1}.suggestion-info strong,.suggestion-info small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.suggestion-info small{color:var(--muted);margin-top:4px}.small-action{padding:6px 9px;font-size:12px;background:transparent;color:var(--blue)}.avatar-small,.avatar-fallback{width:40px;height:40px;border-radius:50%;object-fit:cover;background:#29292f;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0}.card{max-width:520px;margin:28px auto;background:var(--panel);padding:24px;border:1px solid var(--line);border-radius:14px}.flash{max-width:900px;margin:12px auto;padding:12px;background:#48232a;border-radius:8px}.profile{display:grid;grid-template-columns:180px 1fr;gap:30px;padding:20px 0 30px;border-bottom:1px solid var(--line)}.avatar{width:140px;height:140px;object-fit:cover;border-radius:50%;background:#29292f}.avatar-placeholder{width:140px;height:140px;border-radius:50%;background:#29292f;display:grid;place-items:center;font-size:30px}.stats{display:flex;gap:22px;margin:18px 0;flex-wrap:wrap}.actions{display:flex;gap:8px;flex-wrap:wrap}.tabs{display:flex;justify-content:center;gap:28px;padding:18px}.tabs a{color:var(--muted);letter-spacing:1px}.tabs .active{color:var(--text);font-weight:bold;border-top:2px solid;padding-top:14px;margin-top:-16px}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:4px}.tile{aspect-ratio:1;background:#19191e;overflow:hidden}.tile img,.tile video{width:100%;height:100%;object-fit:cover}.post{background:var(--panel);border:1px solid var(--line);border-radius:14px;margin:0 auto 22px;max-width:620px;overflow:hidden}.post-head{padding:13px 15px;display:flex;align-items:center;gap:10px}.post-owner{min-width:0;flex:1}.post-owner strong{display:block}.post-owner .muted{margin-top:3px}.post-media{display:block;width:100%;max-height:680px;object-fit:contain;background:#050505}.post-media video{display:block;width:100%;max-height:680px}.post-body{padding:12px 15px}.post-actions{display:flex;gap:15px;align-items:center}.icon-btn{background:transparent;color:var(--text);padding:5px 3px;font-size:23px;line-height:1}.icon-btn:hover{background:transparent;opacity:.75}.icon-btn.liked{color:var(--red)}.icon-btn.saved{color:var(--blue)}.like-count{font-weight:700;margin:7px 0}.caption{line-height:1.5;overflow-wrap:anywhere}.comment-list{margin:8px 0}.comment{font-size:14px;margin:7px 0;overflow-wrap:anywhere}.inline-form{display:flex;gap:8px;padding:8px 0 0}.inline-form input{margin:0;min-width:0;background:transparent;border:0;border-top:1px solid var(--line);border-radius:0;padding-left:0}.inline-form button{width:auto;white-space:nowrap;background:transparent;color:var(--blue);padding-right:0}.muted{color:var(--muted);font-size:12px}.empty{text-align:center;padding:35px;color:var(--muted)}.user-row{padding:14px;background:var(--panel);border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:10px;align-items:center}.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#28282f;border:1px solid #444;padding:11px 16px;border-radius:10px;z-index:100;box-shadow:0 8px 30px #0008}.messages-shortcut{position:fixed;right:25px;bottom:22px;background:#202025;border:1px solid #3b3b43;border-radius:25px;padding:13px 18px;box-shadow:0 5px 25px #0006;z-index:15}.messages-shortcut:hover{background:#303038}.loading{opacity:.65;pointer-events:none}.footer-note{color:#666;font-size:12px;line-height:1.7;margin-top:30px}.auth-main{margin-left:0;display:grid;place-items:center;min-height:100vh;padding:24px}.auth-main .card{width:min(100%,420px);margin:0;padding:30px}.auth-main .card h1{text-align:center;margin-top:0}.auth-main .card button{width:100%;margin-top:5px}.settings-layout{display:grid;grid-template-columns:250px minmax(0,1fr);gap:20px;max-width:1100px;margin:0 auto}.settings-menu,.settings-panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;overflow:hidden}.settings-menu{padding:16px}.settings-menu h2{margin:8px 8px 16px}.settings-search{margin:0 0 12px}.settings-category{display:flex;align-items:center;gap:10px;width:100%;text-align:left;background:transparent;color:var(--text);padding:12px;border-radius:9px;margin:2px 0}.settings-category.active,.settings-category:hover{background:#29292f}.settings-panel{padding:24px;min-height:420px}.setting-row{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:16px 0;border-bottom:1px solid var(--line)}.setting-row:last-child{border-bottom:0}.setting-copy{min-width:0}.setting-copy strong{display:block;margin-bottom:5px}.setting-copy p{color:var(--muted);font-size:13px;line-height:1.5;margin:0}.setting-control{flex-shrink:0}.setting-control select,.setting-control input[type=text],.setting-control input[type=number]{width:auto;min-width:120px;margin:0;background:#19191e;color:var(--text);border:1px solid #393941;border-radius:8px;padding:9px}.switch{width:44px;height:25px;appearance:none;background:#484850;border-radius:20px;position:relative;cursor:pointer;transition:.2s;margin:0}.switch:before{content:"";position:absolute;width:19px;height:19px;top:3px;left:3px;background:white;border-radius:50%;transition:.2s}.switch:checked{background:var(--blue)}.switch:checked:before{left:22px}.settings-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:20px}.settings-notice{padding:14px;border:1px solid var(--line);background:#19191e;border-radius:10px;color:var(--muted);line-height:1.6}.setting-row[hidden]{display:none}

/* Reels desktop layout */
.stories-strip{scrollbar-width:none}.stories-strip::-webkit-scrollbar{display:none}
.main-area:has(.reels-page){background:#0c0f12;min-height:100dvh;padding:0;overflow:hidden}
body:has(.reels-page){background:#0c0f12;overflow:hidden}
.reels-page{height:100dvh;min-height:0;display:flex;flex-direction:column;align-items:stretch;justify-content:flex-start;gap:0;position:relative;background:#0c0f12;color:#fff;padding:0 34px 0 12px;overflow-y:auto;overflow-x:hidden;overscroll-behavior-y:contain;scroll-snap-type:y mandatory;scrollbar-width:none}.reels-page::-webkit-scrollbar{display:none}.reel-item{min-height:100%;height:100%;width:100%;flex:0 0 100%;display:flex;align-items:center;justify-content:center;gap:18px;scroll-snap-align:start}
.reels-stage{height:min(86dvh,720px);aspect-ratio:9/16;max-width:calc(100vw - 220px);position:relative;border-radius:12px;overflow:hidden;background:#17191d;box-shadow:0 8px 35px #0008;flex-shrink:0}
.reels-stage video{width:100%;height:100%;object-fit:cover;display:block;background:#050505}
.reel-overlay{position:absolute;inset:0;display:flex;flex-direction:column;justify-content:flex-end;padding:16px;background:linear-gradient(transparent 45%,#000b 100%);pointer-events:none}
.reel-creator{display:flex;align-items:center;gap:9px;margin-bottom:9px;pointer-events:auto}.reel-creator img,.reel-avatar{width:34px;height:34px;border-radius:50%;object-fit:cover;background:#333}.reel-creator strong{font-size:13px}.reel-follow{background:transparent;border:1px solid #aaa;padding:6px 10px;border-radius:7px;font-size:12px}.reel-caption{font-size:13px;line-height:1.45;max-width:100%;overflow-wrap:anywhere;margin:0 0 10px}.reel-audio{font-size:11px;color:#eee;margin-bottom:4px}.reel-toolbar{display:flex;flex-direction:column;gap:18px;align-self:center;justify-content:flex-end;padding:0 0 15px}.reel-tool{display:flex;flex-direction:column;align-items:center;gap:4px;color:#fff;background:transparent;padding:4px;font-size:25px}.reel-tool small{font-size:11px}.reel-tool form{margin:0}.reel-tool button{background:transparent;color:#fff;padding:0;font-size:25px}.reel-tool .liked{color:#ff375f}.reel-arrows{position:fixed;right:25px;top:50%;transform:translateY(-50%);display:flex;flex-direction:column;gap:12px;z-index:12}.reel-arrow{border-radius:50%;background:#292d32;color:#fff;width:42px;height:42px;padding:0;font-size:22px}.reel-empty{color:#ddd;text-align:center;max-width:360px;padding:25px}.reel-empty a{margin-top:12px}.reels-page .messages-launcher{position:fixed;right:24px;bottom:22px;background:#202328;border:1px solid #383c42;border-radius:28px;padding:14px 20px;z-index:30}
@media(max-width:1100px){.reels-page{margin-left:0;padding-left:0}.main-area:has(.reels-page){margin-left:76px}.reels-stage{height:min(82dvh,680px);max-width:calc(100vw - 210px)}}
@media(max-width:650px){.main-area:has(.reels-page){margin-left:0;padding:0 0 62px}.reels-page{height:calc(100dvh - 62px);padding:0;gap:0}.reel-item{gap:5px}.reels-stage{height:100%;max-height:none;max-width:calc(100vw - 74px);border-radius:0}.reel-toolbar{gap:12px;padding-right:3px}.reel-tool,.reel-tool button{font-size:22px}.reel-arrows{right:7px;top:42%;gap:8px}.reel-arrow{width:32px;height:32px;font-size:17px}.reels-page .messages-launcher{right:9px;bottom:72px;padding:10px 12px}.reel-caption{font-size:12px}}

@media(max-width:1100px){.sidebar{width:76px;padding:22px 9px}.brand{font-size:0;padding:0 10px 25px}.brand:after{content:'I';font-size:26px}.navlink{justify-content:center;padding:13px 8px}.navlabel{display:none}.main-area{margin-left:76px;padding:22px 20px}.feed-layout{grid-template-columns:minmax(0,620px)}.right-sidebar{display:none}}
@media(max-width:800px){.settings-layout{grid-template-columns:1fr}.settings-menu{padding:12px}.settings-menu .settings-category{display:inline-flex;width:auto}.settings-panel{padding:18px}}
@media(max-width:650px){.auth-main{padding:18px}.auth-main .card{margin:0;width:100%;padding:24px 20px}.setting-row{align-items:flex-start}.setting-control select{min-width:105px;max-width:140px}.settings-actions button{flex:1}.sidebar{inset:auto 0 0 0;width:100%;height:62px;padding:5px 8px;border-right:0;border-top:1px solid var(--line);flex-direction:row;align-items:center}.brand,.navbottom{display:none}.navlinks{display:flex;width:100%;justify-content:space-around;gap:0}.navlink{padding:10px 9px}.main-area{margin-left:0;padding:12px 0 75px}.container{width:100%;margin:0}.post{border-radius:0;border-left:0;border-right:0;margin-bottom:12px}.card{margin:12px;padding:18px}.profile{grid-template-columns:85px 1fr;gap:12px;padding:15px}.avatar,.avatar-placeholder{width:76px;height:76px}.stats{gap:10px;font-size:13px}.tabs{gap:14px;font-size:12px}.messages-shortcut{right:12px;bottom:72px;padding:10px 13px}.flash{margin:8px}}

/* Theme overrides */
html[data-theme="light"]{color-scheme:light;--bg:#f7f7fa;--panel:#ffffff;--line:#e3e3e8;--text:#17171b;--muted:#686875;--blue:#1877f2;--red:#e1306c}
html[data-theme="light"] body,html[data-theme="light"] .sidebar{background:var(--bg);color:var(--text)}
html[data-theme="light"] .navlink{color:var(--text)}
html[data-theme="light"] .navlink:hover,html[data-theme="light"] .navlink.active,html[data-theme="light"] .settings-category.active,html[data-theme="light"] .settings-category:hover{background:#ececf2}
html[data-theme="light"] input,html[data-theme="light"] textarea,html[data-theme="light"] .setting-control select,html[data-theme="light"] .setting-control input[type=text],html[data-theme="light"] .setting-control input[type=number]{background:#fff;color:var(--text);border-color:#d4d4dc}
html[data-theme="light"] .secondary,html[data-theme="light"] .messages-shortcut{background:#ededf3;color:var(--text);border-color:#dedee6}
html[data-theme="light"] .settings-notice{background:#f1f1f6}
.navicon{font-size:25px;width:30px}
.navlink{gap:16px;padding:14px 15px}
.stories-strip{display:flex;gap:15px;overflow-x:auto;padding:14px 12px 18px;margin:0 0 18px;background:var(--panel);border:1px solid var(--line);border-radius:14px;scrollbar-width:thin}
.story-item{flex:0 0 70px;text-align:center;font-size:11px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.story-ring{width:62px;height:62px;border-radius:50%;padding:3px;margin:0 auto 7px;background:linear-gradient(45deg,#ffb000,#ff315a,#a42cff);display:grid;place-items:center}
.story-inner{width:100%;height:100%;border-radius:50%;border:3px solid var(--panel);background:#29292f;display:grid;place-items:center;overflow:hidden;color:#fff;font-size:22px;font-weight:700}
.story-inner img{width:100%;height:100%;object-fit:cover}

/* Instagram-inspired stories, vertical reels and messaging UI */
.stories-strip{gap:20px;padding:20px 18px 22px;margin:0 0 18px;min-height:132px}
.story-item{flex-basis:88px;font-size:12px}
.story-ring{width:78px;height:78px;padding:3px;margin-bottom:8px}
.story-inner{font-size:27px}
.reels-feed{height:calc(100vh - 40px);min-height:520px;overflow-y:auto;overscroll-behavior-y:contain;scroll-snap-type:y mandatory;scrollbar-width:thin;max-width:720px;margin:0 auto}
.reel-card{scroll-snap-align:start;scroll-snap-stop:always;min-height:calc(100vh - 48px);display:flex;flex-direction:column;justify-content:center;margin:0 auto 14px;max-width:620px;width:100%}
.reel-card .post-media{max-height:calc(100vh - 190px);width:100%;object-fit:contain}
.reel-card .post-body{flex-shrink:0}
.messages-launcher{position:fixed;right:29px;bottom:12px;z-index:80;background:#202124;border:1px solid #3a3b40;border-radius:28px;padding:13px 18px;box-shadow:0 8px 30px #0008;color:#f5f5f7}
.messages-panel{position:fixed;right:29px;bottom:12px;width:324px;height:470px;max-height:calc(100dvh - 24px);z-index:90;background:#202124;border:1px solid #3a3b40;border-radius:13px;box-shadow:0 12px 42px #0009;display:none;flex-direction:column;overflow:hidden;color:#f5f5f7}
.messages-panel.open{display:flex}.messages-panel.expanded{width:min(720px,calc(100vw - 100px));height:min(700px,calc(100dvh - 24px))}
.messages-panel-header{height:52px;min-height:52px;display:flex;align-items:center;justify-content:space-between;padding:0 14px;border-bottom:1px solid #38393e;font-weight:700}
.messages-panel-actions{display:flex;gap:5px}.messages-panel-actions button{background:transparent;color:#eee;padding:6px;font-size:18px}
.messages-panel-list{flex:1;min-height:0;overflow-y:auto;padding:12px}
.messages-panel-empty{text-align:center;color:#b4b5bb;padding:36px 12px;line-height:1.6}
.messages-compose{position:absolute;right:13px;bottom:13px;width:50px;height:50px;border-radius:50%;font-size:22px;padding:0;background:#4c5bfa;color:white;box-shadow:0 5px 18px #0008}
.mobile-back{display:none}.inbox-layout{height:calc(100dvh - 52px);min-height:520px;display:grid;grid-template-columns:360px minmax(0,1fr);max-width:1400px;margin:0 auto;background:#0c0f12;color:#f5f5f7;border:1px solid #292d31;border-radius:12px;overflow:hidden}
.inbox-left{min-width:0;border-right:1px solid #292d31;display:flex;flex-direction:column;position:relative}
.inbox-head{padding:24px 18px 12px}.inbox-account{display:flex;align-items:center;justify-content:space-between;font-size:20px;font-weight:700;gap:10px}.inbox-tabs{display:flex;gap:24px;margin-top:22px;border-bottom:1px solid #292d31}.inbox-tabs button{background:transparent;color:#9b9da4;border-radius:0;padding:10px 0;font-weight:600}.inbox-tabs button.active{color:#fff;border-bottom:2px solid #fff}
.inbox-search{padding:12px 16px 4px}.inbox-search input{margin:0;background:#1c2025;border:0;border-radius:10px}.inbox-notes{display:flex;gap:15px;overflow-x:auto;padding:12px 16px 16px;border-bottom:1px solid #292d31}.inbox-note{min-width:60px;text-align:center;font-size:11px;color:#a1a1aa}.inbox-note .avatar-small{width:48px;height:48px;margin-bottom:6px}.conversation-list{overflow-y:auto;flex:1;min-height:0}.conversation-row{display:flex;gap:12px;align-items:center;padding:12px 16px;min-height:76px;transition:background .15s}.conversation-row:hover,.conversation-row.selected{background:#1b2026}.conversation-row .avatar-small,.conversation-row .avatar-fallback{width:48px;height:48px}.conversation-copy{min-width:0;flex:1}.conversation-copy strong,.conversation-copy span{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.conversation-copy span{color:#9b9da4;font-size:12px;margin-top:5px}.conversation-time{font-size:11px;color:#8b8d94;align-self:flex-start;margin-top:4px}.inbox-main{display:flex;flex-direction:column;min-width:0;min-height:0;background:#0c0f12}.chat-header{height:72px;flex-shrink:0;display:flex;align-items:center;gap:12px;padding:12px 22px;border-bottom:1px solid #292d31}.chat-header .avatar-small{width:42px;height:42px}.chat-scroll{flex:1;min-height:0;overflow-y:auto;padding:22px;display:flex;flex-direction:column;gap:12px}.chat-empty{margin:auto;text-align:center;color:#a1a1aa;max-width:330px}.chat-empty .send-icon{font-size:32px;border:1px solid #666;border-radius:50%;width:72px;height:72px;display:grid;place-items:center;margin:0 auto 18px;color:#fff}.chat-empty h2{color:#f5f5f7}.chat-empty .btn{background:#4c5bfa}.chat-bubble{max-width:min(70%,480px);padding:11px 15px;border-radius:20px;background:#242a31;overflow-wrap:anywhere;align-self:flex-start}.chat-bubble.outgoing{align-self:flex-end;background:#4c5bfa}.chat-composer{flex-shrink:0;display:flex;align-items:center;gap:8px;margin:14px 18px 18px;border:1px solid #393d43;border-radius:25px;padding:5px 8px 5px 15px}.chat-composer input{min-width:0;margin:0;border:0;background:transparent;padding:9px 0}.chat-composer button{background:transparent;color:#aebaff;padding:8px}
@media(max-width:850px){.inbox-layout{grid-template-columns:300px minmax(0,1fr)}}
@media(max-width:650px){.stories-strip{gap:16px;padding:17px 14px 20px;min-height:126px}.story-item{flex-basis:82px}.story-ring{width:72px;height:72px}.reels-feed{height:calc(100dvh - 80px);min-height:440px}.reel-card{min-height:calc(100dvh - 86px);margin-bottom:8px}.reel-card .post-media{max-height:calc(100dvh - 220px)}.messages-launcher{right:12px;bottom:72px}.messages-panel{right:8px;bottom:68px;width:calc(100vw - 16px);height:min(470px,calc(100dvh - 82px))}.messages-panel.expanded{width:calc(100vw - 16px);height:calc(100dvh - 82px)}.inbox-layout{height:calc(100dvh - 82px);min-height:0;display:block;border-radius:0;border:0}.inbox-left{height:100%;border-right:0}.inbox-layout.chat-selected .inbox-left{display:none}.inbox-main{display:none;height:100%}.inbox-layout.chat-selected .inbox-main{display:flex}.inbox-layout:not(.chat-selected) .inbox-main{display:none}.mobile-back{display:inline-flex;padding:6px 8px;background:transparent;color:#fff}.inbox-head{padding:16px 14px 8px}.inbox-tabs{gap:20px}.inbox-notes{padding:10px 12px}.chat-header{height:64px;padding:10px 12px}.chat-scroll{padding:14px}.chat-composer{margin:10px 10px 12px}.main-area{padding-top:0}}

/* Badges, unread states, notifications, chat extras */
[hidden]{display:none!important}
.navicon{position:relative}
.nav-badge{position:absolute;top:-7px;right:-9px;min-width:18px;height:18px;padding:0 5px;border-radius:9px;background:var(--red);color:#fff;font-size:11px;font-weight:700;line-height:18px;text-align:center}
.unread-pill{background:var(--blue);color:#fff;border-radius:10px;min-width:20px;padding:1px 6px;font-size:11px;font-weight:700;text-align:center}
.conversation-meta{display:flex;flex-direction:column;align-items:flex-end;gap:6px;align-self:flex-start;margin-top:4px}.conversation-meta .conversation-time{margin:0}
.conversation-row.unread strong,.conversation-row.unread .conversation-copy span{color:#fff;font-weight:700}
.list-heading{padding:12px 16px 4px;color:#9b9da4;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.5px}
.chat-text{white-space:pre-wrap}.chat-time{display:block;margin-top:4px;font-size:10px;opacity:.65}
.chat-composer textarea{min-height:0;height:38px;max-height:120px;resize:none;margin:0;border:0;background:transparent;padding:9px 0;line-height:20px;outline:none}
.notif-row{display:flex;align-items:center;gap:10px;padding:12px 14px;border-bottom:1px solid var(--line);border-left:3px solid transparent;opacity:.75}
.notif-row.unread{opacity:1;background:rgba(79,156,255,.12);border-left-color:var(--blue)}
.notif-link{display:flex;align-items:center;gap:12px;flex:1;min-width:0}.notif-text{flex:1;min-width:0;overflow-wrap:anywhere}
.notif-head{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:10px}
.reel-comment{display:flex;gap:6px;pointer-events:auto;margin-top:6px}.reel-comment input{margin:0;padding:8px 12px;border-radius:18px;background:#0009;border:1px solid #fff4;color:#fff;font-size:13px}.reel-comment button{background:transparent;color:#8ab4ff;padding:6px 8px}

</style><script>try{const savedTheme=localStorage.getItem('instaclone-theme');if(savedTheme==='Light')document.documentElement.dataset.theme='light';else document.documentElement.dataset.theme='dark'}catch(e){}</script><script>window.CSRF="{{ csrf_token() }}";</script></head><body><div class="app-shell">
{% if session.get('user_id') %}<aside class="sidebar"><a class="brand" href="{{ url_for('home') }}">InstaClone</a><div class="navlinks">
<a class="navlink" href="{{ url_for('home') }}"><span class="navicon">⌂</span><span class="navlabel">Home</span></a>
<a class="navlink" href="{{ url_for('reels') }}"><span class="navicon">▣</span><span class="navlabel">Reels</span></a>
<a class="navlink" href="{{ url_for('messages_page') }}"><span class="navicon">✉<span class="nav-badge" id="badge-messages" hidden></span></span><span class="navlabel">Messages</span></a>
<a class="navlink" href="{{ url_for('search_users') }}"><span class="navicon">⌕</span><span class="navlabel">Search</span></a>
<a class="navlink" href="{{ url_for('notifications_page') }}"><span class="navicon">♧<span class="nav-badge" id="badge-notifications" hidden></span></span><span class="navlabel">Notifications</span></a>
<a class="navlink" href="{{ url_for('create_post') }}"><span class="navicon">＋</span><span class="navlabel">Create post</span></a>
<a class="navlink" href="{{ url_for('profile') }}"><span class="navicon">◉</span><span class="navlabel">Profile</span></a>
<a class="navlink" href="{{ url_for('saved_posts') }}"><span class="navicon">▱</span><span class="navlabel">Saved</span></a>
</div><div class="navbottom"><a class="navlink" href="{{ url_for('settings_page') }}"><span class="navicon">☰</span><span class="navlabel">Settings / Logout</span></a></div></aside>{% endif %}
<main class="main-area {% if not session.get('user_id') %}auth-main{% endif %}">{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="flash">{{ message }}</div>{% endfor %}{% endwith %}{{ content|safe }}</main>
{% if session.get('user_id') %}<button id="messages-launcher" class="messages-launcher" type="button" aria-label="Open Messages">✉ &nbsp; Messages</button><section id="floating-messages" class="messages-panel" aria-label="Messages panel" aria-hidden="true"><header class="messages-panel-header"><span>Messages</span><div class="messages-panel-actions"><button type="button" id="messages-expand" aria-label="Open full inbox" title="Open inbox">↗</button><button type="button" id="messages-close" aria-label="Close Messages" title="Close">×</button></div></header><div class="messages-panel-list"><div class="messages-panel-empty"><div style="font-size:34px;margin-bottom:10px">✉</div><strong>No conversations yet</strong><div>Find people and start a conversation.</div><a class="btn" style="margin-top:15px" href="{{ url_for('messages_page') }}">Open inbox</a></div></div><button class="messages-compose" id="messages-compose" type="button" aria-label="Compose new message" title="New message">✎</button></section>{% endif %}<div id="toast" class="toast" hidden></div></div>
<script>
(() => { const panel=document.getElementById('floating-messages'), launcher=document.getElementById('messages-launcher'); if(!panel||!launcher)return; const close=()=>{panel.classList.remove('open','expanded');panel.setAttribute('aria-hidden','true');launcher.hidden=false}; const esc=value=>String(value??'').replace(/[&<>\"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[ch])); const loadPreview=async()=>{const list=panel.querySelector('.messages-panel-list');try{const response=await fetch('{{ url_for("messages_preview") }}',{credentials:'same-origin',headers:{'Accept':'application/json'}});if(!response.ok)return;const data=await response.json();if(!data.users||!data.users.length)return;list.innerHTML=data.users.map(u=>`<a class="conversation-row${u.unread?' unread':''}" style="padding:10px 2px" href="/messages?user_id=${u.id}">${u.avatar ? `<img class="avatar-small" src="${esc(u.avatar)}" alt="">` : `<span class="avatar-fallback">${esc(u.initial)}</span>`}<div class="conversation-copy"><strong>${esc(u.name)}</strong><span>${esc(u.snippet)}</span></div><div class="conversation-meta"><span class="conversation-time">${esc(u.time||'')}</span>${u.unread?`<span class="unread-pill">${u.unread}</span>`:''}</div></a>`).join('')+`<a class="btn" style="display:flex;margin:8px 0 55px" href="{{ url_for('messages_page') }}">Open inbox</a>`;}catch(e){}}; launcher.addEventListener('click',()=>{panel.classList.add('open');panel.setAttribute('aria-hidden','false');launcher.hidden=true;loadPreview()}); document.getElementById('messages-close').addEventListener('click',close); document.getElementById('messages-expand').addEventListener('click',()=>location.href='{{ url_for("messages_page") }}'); document.getElementById('messages-compose').addEventListener('click',()=>location.href='{{ url_for("messages_page") }}?compose=1'); })();
</script>
<script>
(() => {
 const toast = (message) => { const el=document.getElementById('toast'); if(!el)return; el.textContent=message; el.hidden=false; clearTimeout(window.__toastTimer); window.__toastTimer=setTimeout(()=>el.hidden=true,2600); };
 window.toast = toast;

 // CSRF: add the token to every POST form on the page
 document.querySelectorAll('form[method="post"]').forEach(f=>{ if(!f.querySelector('input[name="csrf_token"]')){ const i=document.createElement('input'); i.type='hidden'; i.name='csrf_token'; i.value=window.CSRF; f.appendChild(i); } });

 document.addEventListener('submit', async (event) => {
   const form=event.target;
   if(!form.matches || !form.matches('form[data-ajax]')) return;
   event.preventDefault();
   const submit=form.querySelector('button[type="submit"],button:not([type])');
   if(form.dataset.busy==='1') return;
   form.dataset.busy='1'; if(submit)submit.disabled=true;
   try {
     const response=await fetch(form.action,{method:'POST',body:new FormData(form),credentials:'same-origin',headers:{'X-Requested-With':'XMLHttpRequest','Accept':'application/json','X-CSRFToken':window.CSRF}});
     let data; try { data=await response.json(); } catch(e) { throw new Error('Unexpected server response. Please refresh the page.'); }
     if(!response.ok||!data.ok) throw new Error(data.message||'The request could not be completed.');
     const scope=form.closest('.reel-item')||form.closest('[data-post-id]');
     if(form.dataset.ajax==='like'){
       const btn=form.querySelector('button');
       btn.classList.toggle('liked',data.liked); btn.setAttribute('aria-label',data.liked?'Unlike post':'Like post'); btn.innerHTML=data.liked?'♥':'♡';
       const count=scope&&scope.querySelector('[data-like-count]'); if(count)count.textContent=data.count+(count.dataset.suffix||'');
     } else if(form.dataset.ajax==='save'){
       const btn=form.querySelector('button'); btn.classList.toggle('saved',data.saved); btn.setAttribute('aria-label',data.saved?'Remove from saved':'Save post'); btn.innerHTML=data.saved?'▣':'▱'; toast(data.saved?'Post saved':'Post removed from Saved');
     } else if(form.dataset.ajax==='comment'){
       const list=scope&&scope.querySelector('.comment-list');
       if(list){ const row=document.createElement('p'); row.className='comment'; const strong=document.createElement('strong'); strong.textContent='@'+data.username+' '; row.append(strong,document.createTextNode(data.comment)); list.appendChild(row); }
       form.reset();
       const count=scope&&scope.querySelector('[data-comment-count]'); if(count)count.textContent=data.comment_count+(count.dataset.suffix||'');
       toast('Comment posted');
     } else if(form.dataset.ajax==='follow'){
       document.querySelectorAll('form[data-ajax="follow"]').forEach(f=>{ if(f.action!==form.action)return; const b=f.querySelector('button'); if(!b)return; b.textContent=data.following?'Following':'Follow'; b.classList.toggle('secondary',data.following); });
       if(typeof data.followers==='number') document.querySelectorAll('[data-followers-count]').forEach(el=>el.textContent=data.followers);
       toast(data.following?'User followed':'User unfollowed');
     }
   } catch(error) { toast(error.message||'Network error. Please try again.'); }
   finally {form.dataset.busy='0'; if(submit)submit.disabled=false;}
 });

 document.addEventListener('click', (event) => {
   const focusBtn=event.target.closest('[data-focus-comment]');
   if(focusBtn){ const scope=focusBtn.closest('[data-post-id]'); const input=scope&&scope.querySelector('input[name="comment"]'); if(input)input.focus(); }
   const reelBtn=event.target.closest('[data-toggle-reel-comment]');
   if(reelBtn){ const f=reelBtn.closest('.reel-item').querySelector('.reel-comment'); if(f){ f.hidden=!f.hidden; if(!f.hidden)f.querySelector('input').focus(); } }
 });

 // Unread badges: lightweight polling (this is polling, not server push)
 let last={m:0,n:0,init:false};
 const setBadge=(id,n)=>{ const el=document.getElementById(id); if(!el)return; el.textContent=n>99?'99+':String(n); el.hidden=!(n>0); };
 async function refreshCounters(){
   if(document.hidden && last.init) return;
   try{
     const r=await fetch('/api/counters',{credentials:'same-origin',headers:{'Accept':'application/json'}});
     if(!r.ok) return; const d=await r.json(); if(!d.ok) return;
     setBadge('badge-messages',d.messages); setBadge('badge-notifications',d.notifications);
     if(last.init && 'Notification' in window && Notification.permission==='granted' && (d.messages>last.m || d.notifications>last.n)){
       new Notification('InstaClone',{body:d.messages>last.m?'You have a new message':'You have new notifications'});
     }
     last={m:d.messages,n:d.notifications,init:true};
   }catch(e){}
 }
 window.refreshCounters=refreshCounters;
 if(document.getElementById('badge-messages')){ refreshCounters(); setInterval(refreshCounters,10000); }
})();
</script></body></html>'''


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            if is_ajax() or request.headers.get("Accept", "").startswith("application/json"):
                return jsonify(ok=False, message="Please log in again."), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def fail(message, status=400, fallback=None):
    """Return a JSON error for AJAX calls, or flash + redirect for normal forms."""
    if is_ajax():
        return jsonify(ok=False, message=message), status
    flash(message)
    return redirect(request.referrer or fallback or url_for("home"))


# ---------------------------------------------------------------------------
# Schema management (idempotent, never drops or truncates anything)
# ---------------------------------------------------------------------------
def ensure_saved_posts_table(cursor):
    cursor.execute("""
        IF OBJECT_ID('dbo.SavedPosts', 'U') IS NULL
        BEGIN
            CREATE TABLE dbo.SavedPosts (
                SavedPostID INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
                UserID INT NOT NULL,
                PostID INT NOT NULL,
                CreatedAt DATETIME2 NOT NULL CONSTRAINT DF_SavedPosts_CreatedAt DEFAULT SYSUTCDATETIME(),
                CONSTRAINT UQ_SavedPosts_User_Post UNIQUE (UserID, PostID)
            );
        END
    """)


def ensure_notifications_table(cur):
    cur.execute("""IF OBJECT_ID('dbo.Notifications','U') IS NULL
    CREATE TABLE dbo.Notifications(
      NotificationID INT IDENTITY(1,1) PRIMARY KEY,
      UserID INT NOT NULL, ActorID INT NOT NULL,
      NotificationType NVARCHAR(30) NOT NULL,
      PostID INT NULL, IsRead BIT NOT NULL CONSTRAINT DF_Notifications_IsRead DEFAULT(0),
      CreatedAt DATETIME2 NOT NULL CONSTRAINT DF_Notifications_CreatedAt DEFAULT SYSDATETIME()
    )""")
    # Safely add optional columns if an older version of the table lacks them
    cur.execute("IF COL_LENGTH('dbo.Notifications','PostID') IS NULL ALTER TABLE dbo.Notifications ADD PostID INT NULL")
    cur.execute("IF COL_LENGTH('dbo.Notifications','IsRead') IS NULL ALTER TABLE dbo.Notifications ADD IsRead BIT NOT NULL CONSTRAINT DF_Notifications_IsRead2 DEFAULT(0)")
    cur.execute("IF COL_LENGTH('dbo.Notifications','CreatedAt') IS NULL ALTER TABLE dbo.Notifications ADD CreatedAt DATETIME2 NOT NULL CONSTRAINT DF_Notifications_CreatedAt2 DEFAULT SYSDATETIME()")


def ensure_messages_table(cur):
    cur.execute("""IF OBJECT_ID('dbo.Messages','U') IS NULL
    CREATE TABLE dbo.Messages(
      MessageID INT IDENTITY(1,1) PRIMARY KEY,
      SenderID INT NOT NULL, ReceiverID INT NOT NULL,
      MessageText NVARCHAR(2000) NOT NULL,
      SentAt DATETIME2 NOT NULL CONSTRAINT DF_Messages_SentAt DEFAULT SYSDATETIME(),
      IsRead BIT NOT NULL CONSTRAINT DF_Messages_IsRead DEFAULT(0)
    )""")
    cur.execute("IF COL_LENGTH('dbo.Messages','IsRead') IS NULL ALTER TABLE dbo.Messages ADD IsRead BIT NOT NULL CONSTRAINT DF_Messages_IsRead2 DEFAULT(0)")
    cur.execute("IF COL_LENGTH('dbo.Messages','SentAt') IS NULL ALTER TABLE dbo.Messages ADD SentAt DATETIME2 NOT NULL CONSTRAINT DF_Messages_SentAt2 DEFAULT SYSDATETIME()")


def ensure_indexes(cur):
    statements = [
        "IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='IX_Messages_Conversation' AND object_id=OBJECT_ID('dbo.Messages')) CREATE INDEX IX_Messages_Conversation ON dbo.Messages(SenderID, ReceiverID, MessageID)",
        "IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='IX_Messages_Unread' AND object_id=OBJECT_ID('dbo.Messages')) CREATE INDEX IX_Messages_Unread ON dbo.Messages(ReceiverID, IsRead, SenderID)",
        "IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='IX_Notifications_User' AND object_id=OBJECT_ID('dbo.Notifications')) CREATE INDEX IX_Notifications_User ON dbo.Notifications(UserID, IsRead, NotificationID)",
    ]
    for sql in statements:
        try:
            cur.execute(sql)
        except Exception:
            app.logger.exception("Index creation skipped: %s", sql[:80])


_schema_ready = False
_schema_next_try = 0.0
_schema_lock = threading.Lock()


def ensure_schema():
    """Run the idempotent table/index checks once per process (retry every 60 s on failure)."""
    global _schema_ready, _schema_next_try
    if _schema_ready or time.time() < _schema_next_try:
        return
    with _schema_lock:
        if _schema_ready or time.time() < _schema_next_try:
            return
        ok = True
        conn = None
        try:
            conn = _raw_get_connection()
            for step in (ensure_saved_posts_table, ensure_notifications_table, ensure_messages_table, ensure_indexes):
                try:
                    cur = conn.cursor()
                    step(cur)
                    conn.commit()
                except Exception:
                    ok = False
                    conn.rollback()
                    app.logger.exception("Schema step %s failed", step.__name__)
        except Exception:
            ok = False
            app.logger.exception("Schema check could not connect to SQL Server")
        finally:
            if conn:
                conn.close()
        _schema_ready = ok
        if not ok:
            _schema_next_try = time.time() + 60


def get_connection():
    ensure_schema()
    return _raw_get_connection()


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------
def columns(cursor, table):
    cursor.execute("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ?", (table,))
    return {row[0].lower(): row[0] for row in cursor.fetchall()}


def pick(cols, *names):
    for name in names:
        if name.lower() in cols:
            return cols[name.lower()]
    return None


def table_features(cursor, table):
    c = columns(cursor, table)
    return c


def insert_dynamic(cursor, table, mapping):
    cols = table_features(cursor, table)
    pairs = []
    for candidates, value in mapping:
        col = pick(cols, *candidates)
        if col:
            pairs.append((col, value))
    if not pairs:
        raise RuntimeError(f"Could not identify columns in table {table}.")
    sql = "INSERT INTO [" + table + "] (" + ", ".join("[" + c + "]" for c, _ in pairs) + ") VALUES (" + ", ".join("?" for _ in pairs) + ")"
    cursor.execute(sql, tuple(v for _, v in pairs))


def save_media(file):
    if not file or not file.filename:
        raise ValueError("Please select a photo or video.")
    original = secure_filename(file.filename)
    ext = os.path.splitext(original)[1].lower()
    if ext in IMAGE_EXTENSIONS:
        kind, limit = "image", MAX_IMAGE_SIZE
    elif ext in VIDEO_EXTENSIONS:
        kind, limit = "video", MAX_VIDEO_SIZE
    else:
        raise ValueError("Only JPG, PNG, and WebP photos and MP4, WebM, or MOV videos are allowed.")
    file.stream.seek(0, os.SEEK_END)
    size = file.stream.tell()
    file.stream.seek(0)
    if size == 0:
        raise ValueError("The selected file is empty.")
    if size > limit:
        raise ValueError("Photos must be 5 MB or smaller and videos must be 50 MB or smaller.")
    header = file.stream.read(16)
    file.stream.seek(0)
    if kind == "image":
        valid = header.startswith(b"\xff\xd8\xff") or header.startswith(b"\x89PNG\r\n\x1a\n") or (header.startswith(b"RIFF") and header[8:12] == b"WEBP")
    else:
        # MP4/MOV normally contain an ftyp marker; WebM starts with EBML bytes.
        valid = (len(header) >= 8 and header[4:8] == b"ftyp") or header.startswith(b"\x1a\x45\xdf\xa3")
    if not valid:
        raise ValueError("The file format is unsupported or does not match its extension.")
    filename = uuid.uuid4().hex + ext
    file.save(os.path.join(UPLOAD_FOLDER, filename))
    return filename, kind


def safe_media_url(filename):
    if filename and os.path.basename(filename) == filename:
        return url_for("static", filename="uploads/" + filename)
    return None


def avatar_html(profile_image, username, cls="avatar-small"):
    url = safe_media_url(profile_image)
    if url:
        return f'<img class="{cls}" src="{escape(url)}" alt="">'
    return f'<span class="avatar-fallback">{escape((str(username or "U")[:1]).upper())}</span>'


def short_time(dt):
    if not isinstance(dt, datetime):
        return str(dt or "")
    now = datetime.now()
    if dt.date() == now.date():
        return dt.strftime("%H:%M")
    if dt.year == now.year:
        return dt.strftime("%b %d")
    return dt.strftime("%b %d, %Y")


def iso(dt):
    return dt.isoformat() if hasattr(dt, "isoformat") else str(dt or "")


def get_user_brief(cur, user_id):
    cur.execute("SELECT UserID,Username,FullName,ProfileImage FROM Users WHERE UserID=?", (user_id,))
    return cur.fetchone()


def followed_people(cur, uid, limit=8):
    """People the current user follows (used as quick-start contacts in Messages)."""
    fcols = columns(cur, "Followers")
    fc = pick(fcols, "FollowerUserID", "FollowerID", "UserID", "Follower")
    gc = pick(fcols, "FollowingUserID", "FollowingID", "FollowedUserID", "Following")
    top = f"TOP {int(limit)} " if limit else ""
    if fc and gc:
        cur.execute(f"SELECT {top}u.UserID,u.Username,u.FullName,u.ProfileImage FROM Users u JOIN Followers f ON f.[{gc}]=u.UserID WHERE f.[{fc}]=? AND u.UserID<>? ORDER BY u.Username", (uid, uid))
    else:
        cur.execute(f"SELECT {top}UserID,Username,FullName,ProfileImage FROM Users WHERE UserID<>? ORDER BY Username", (uid,))
    return cur.fetchall()


def get_posts(cursor, where_sql, params):
    cursor.execute("SELECT p.PostID,p.UserID,p.Caption,p.MediaPath,p.MediaType,p.CreatedAt,u.Username,u.ProfileImage FROM Posts p JOIN Users u ON p.UserID=u.UserID " + where_sql + " ORDER BY p.CreatedAt DESC,p.PostID DESC", params)
    return cursor.fetchall()


def like_state(cursor, post_id, user_id):
    cols = columns(cursor, "Likes")
    post_col = pick(cols, "PostID", "PostId", "Post_ID")
    user_col = pick(cols, "UserID", "LikerUserID", "LikedByUserID", "User_ID")
    if not post_col or not user_col:
        return False, 0
    cursor.execute(f"SELECT COUNT(*) FROM Likes WHERE [{post_col}]=?", (post_id,))
    count = cursor.fetchone()[0]
    cursor.execute(f"SELECT COUNT(*) FROM Likes WHERE [{post_col}]=? AND [{user_col}]=?", (post_id, user_id))
    return cursor.fetchone()[0] > 0, count


def comment_rows(cursor, post_id):
    c = columns(cursor, "Comments")
    post_col = pick(c, "PostID", "PostId", "Post_ID")
    user_col = pick(c, "UserID", "CommenterUserID", "CreatedByUserID", "User_ID")
    text_col = pick(c, "CommentText", "Comment", "Content", "Text", "Body")
    id_col = pick(c, "CommentID", "ID")
    time_col = pick(c, "CreatedAt", "CommentDate", "CreatedOn")
    if not post_col or not text_col:
        return []
    username_col = pick(columns(cursor, "Users"), "Username")
    if user_col and username_col:
        order = f" ORDER BY c.[{time_col}] ASC" if time_col else ""
        cursor.execute(f"SELECT u.[{username_col}],c.[{text_col}] FROM Comments c LEFT JOIN Users u ON c.[{user_col}]=u.UserID WHERE c.[{post_col}]=?" + order, (post_id,))
    else:
        cursor.execute(f"SELECT CAST('user' AS NVARCHAR(100)),[{text_col}] FROM Comments WHERE [{post_col}]=?", (post_id,))
    return cursor.fetchall()


def saved_state(cursor, post_id, user_id):
    ensure_saved_posts_table(cursor)
    cursor.execute("SELECT COUNT(*) FROM dbo.SavedPosts WHERE UserID=? AND PostID=?", (user_id, post_id))
    return cursor.fetchone()[0] > 0


def render_posts(posts, active_user, mode="feed"):
    connection = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        ensure_saved_posts_table(cursor)
        connection.commit()
        cards = []
        for p in posts:
            post_id, owner_id, caption, path, media_type, created, username, profile_image = p
            url = safe_media_url(path)
            media = ""
            if url and media_type == "video":
                media = f'<video class="post-media" controls preload="metadata" playsinline src="{escape(url)}"></video>'
            elif url:
                media = f'<img class="post-media" src="{escape(url)}" alt="Post photo" loading="lazy">'
            liked, like_count = like_state(cursor, post_id, active_user)
            comments = comment_rows(cursor, post_id)
            saved = saved_state(cursor, post_id, active_user)
            avatar_url = safe_media_url(profile_image)
            avatar = f'<img class="avatar-small" src="{escape(avatar_url)}" alt="">' if avatar_url else '<span class="avatar-fallback">●</span>'
            comment_html = "".join(f'<p class="comment"><strong>@{escape(str(c[0] or "user"))}</strong> {escape(str(c[1] or ""))}</p>' for c in comments[-5:])
            follow_form = ""
            if owner_id != active_user:
                fcols = columns(cursor, "Followers")
                follower_col = pick(fcols, "FollowerUserID", "FollowerID", "UserID", "Follower")
                following_col = pick(fcols, "FollowingUserID", "FollowingID", "FollowedUserID", "Following")
                is_following = False
                if follower_col and following_col:
                    cursor.execute(f"SELECT COUNT(*) FROM Followers WHERE [{follower_col}]=? AND [{following_col}]=?", (active_user, owner_id))
                    is_following = cursor.fetchone()[0] > 0
                follow_form = f'<form data-ajax="follow" method="post" action="{url_for("toggle_follow",user_id=owner_id)}"><button type="submit" class="small-action {"secondary" if is_following else ""}">{"Following" if is_following else "Follow"}</button></form>'
            cards.append(f'''<article class="post" data-post-id="{post_id}">
              <div class="post-head">{avatar}<div class="post-owner"><strong><a href="{url_for('user_profile', user_id=owner_id)}">@{escape(str(username))}</a></strong><div class="muted">{escape(str(created))}</div></div>{follow_form}</div>
              {media}<div class="post-body"><div class="post-actions">
              <form data-ajax="like" method="post" action="{url_for('toggle_like', post_id=post_id)}"><button type="submit" class="icon-btn {"liked" if liked else ""}" aria-label="{"Unlike post" if liked else "Like post"}">{"♥" if liked else "♡"}</button></form>
              <button type="button" class="icon-btn" data-focus-comment aria-label="Write a comment">▢</button><span style="flex:1"></span>
              <form data-ajax="save" method="post" action="{url_for('toggle_save',post_id=post_id)}"><button type="submit" class="icon-btn {"saved" if saved else ""}" aria-label="{"Remove from saved" if saved else "Save post"}">{"▣" if saved else "▱"}</button></form></div>
              <div class="like-count" data-like-count data-suffix=" likes">{like_count} likes</div><p class="caption"><strong>@{escape(str(username))}</strong> {escape(str(caption or ''))}</p>
              <div class="muted" data-comment-count data-suffix=" comments">{len(comments)} comments</div><div class="comment-list">{comment_html}</div>
              <form class="inline-form" data-ajax="comment" method="post" action="{url_for('add_comment', post_id=post_id)}"><input name="comment" maxlength="1000" placeholder="Add a comment..." aria-label="Add a comment" required><button type="submit">Post</button></form>
              </div></article>''')
        return "".join(cards) if cards else '<div class="empty"><h2>No posts yet</h2><p>Share a photo or video.</p><a class="btn" href="/create-post">Create post</a></div>'
    finally:
        if connection:
            connection.close()


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------
# One notification per (recipient, actor, type, post) for these - prevents duplicates
# when someone likes, unlikes and likes again, or follows/unfollows repeatedly.
DEDUPE_KINDS = {"follow", "post_like", "reel_like"}


def create_notification(cur, recipient_id, actor_id, kind, post_id=None):
    """Insert a notification inside the caller's transaction. Never notifies a user about their own action."""
    if not recipient_id or not actor_id or int(recipient_id) == int(actor_id):
        return False
    if kind in DEDUPE_KINDS:
        sql = "SELECT TOP 1 1 FROM dbo.Notifications WHERE UserID=? AND ActorID=? AND NotificationType=?"
        params = [recipient_id, actor_id, kind]
        if post_id is None:
            sql += " AND PostID IS NULL"
        else:
            sql += " AND PostID=?"
            params.append(post_id)
        cur.execute(sql, tuple(params))
        if cur.fetchone():
            return False
    elif kind == "message":
        # Collapse a burst of messages into a single unread notification per sender.
        cur.execute("SELECT TOP 1 1 FROM dbo.Notifications WHERE UserID=? AND ActorID=? AND NotificationType='message' AND IsRead=0", (recipient_id, actor_id))
        if cur.fetchone():
            return False
    cur.execute("INSERT INTO dbo.Notifications(UserID,ActorID,NotificationType,PostID,IsRead,CreatedAt) VALUES(?,?,?,?,0,SYSDATETIME())", (recipient_id, actor_id, kind, post_id))
    return True


NOTIFICATION_TEXT = {
    "follow": "started following you.",
    "post_like": "liked your post.",
    "reel_like": "liked your reel.",
    "comment": "commented on your post.",
    "reel_comment": "commented on your reel.",
    "message": "sent you a message.",
}


def notification_target(kind, actor_id, post_id):
    if kind == "message":
        return url_for("messages_page", user_id=actor_id)
    if kind in ("reel_like", "reel_comment") and post_id:
        return url_for("reels", post_id=post_id)
    if kind in ("post_like", "comment") and post_id:
        return url_for("view_post", post_id=post_id)
    return url_for("user_profile", user_id=actor_id)


@app.route("/api/counters")
@login_required
def api_counters():
    """Unread counters for the logged-in user only.
    Messages badge = number of conversations that contain unread messages.
    Notifications badge = number of unread notifications."""
    uid = int(session["user_id"])
    conn = None
    try:
        conn = get_connection(); cur = conn.cursor()
        cur.execute("SELECT COUNT(DISTINCT SenderID) FROM dbo.Messages WHERE ReceiverID=? AND IsRead=0", (uid,))
        m = int(cur.fetchone()[0] or 0)
        cur.execute("SELECT COUNT(*) FROM dbo.Notifications WHERE UserID=? AND IsRead=0", (uid,))
        n = int(cur.fetchone()[0] or 0)
        return jsonify(ok=True, messages=m, notifications=n)
    except Exception:
        app.logger.exception("Counters failed")
        return jsonify(ok=False, messages=0, notifications=0), 500
    finally:
        if conn:
            conn.close()


@app.route("/notifications")
@login_required
def notifications_page():
    conn = None
    try:
        conn = get_connection(); cur = conn.cursor()
        cur.execute("SELECT TOP 100 n.NotificationID,n.ActorID,n.NotificationType,n.PostID,n.IsRead,n.CreatedAt,u.Username,u.ProfileImage FROM dbo.Notifications n JOIN dbo.Users u ON u.UserID=n.ActorID WHERE n.UserID=? ORDER BY n.NotificationID DESC", (session["user_id"],))
        rows = cur.fetchall()
        items = []
        unread_total = 0
        for nid, actor, kind, pid, isread, created, username, profile in rows:
            kind = str(kind)
            text = NOTIFICATION_TEXT.get(kind, "interacted with your account.")
            unread = not bool(isread)
            unread_total += 1 if unread else 0
            btn = f'<button type="button" class="small-action" data-mark-read="{nid}">Mark read</button>' if unread else ""
            items.append(f'<div class="notif-row{" unread" if unread else ""}" data-nid="{nid}"><a class="notif-link" href="{url_for("notification_open", nid=nid)}">{avatar_html(profile, username)}<span class="notif-text"><strong>@{escape(str(username))}</strong> {text}<div class="muted">{escape(short_time(created))}</div></span></a>{btn}</div>')
        head = f'<div class="notif-head"><div><h1 style="margin:0">Notifications</h1><p class="muted">Your recent activity</p></div><div class="actions"><button type="button" class="secondary" id="enable-browser-alerts" hidden>Enable browser alerts</button><button type="button" class="secondary" id="mark-all-read"{"" if unread_total else " hidden"}>Mark all as read</button></div></div>'
        body = "".join(items) if items else '<div class="empty">You have no notifications yet.</div>'
        content = '<div class="container"><div class="card" style="max-width:720px">' + head + body + '</div></div><script>' + NOTIF_JS + '</script>'
        return render_template_string(PAGE, title="Notifications", content=content)
    except Exception:
        app.logger.exception("Notifications failed")
        return "Notifications could not be loaded. Please check the application log.", 500
    finally:
        if conn:
            conn.close()


NOTIF_JS = r'''
(function(){
 const post=async(url)=>{const r=await fetch(url,{method:'POST',credentials:'same-origin',headers:{'X-Requested-With':'XMLHttpRequest','X-CSRFToken':window.CSRF,'Accept':'application/json'}});let d={};try{d=await r.json()}catch(e){}return {r,d}};
 const say=m=>{if(window.toast)window.toast(m)};
 document.addEventListener('click',async e=>{
  const one=e.target.closest('[data-mark-read]');
  if(one){ one.disabled=true; try{ const {r,d}=await post('/notifications/'+one.dataset.markRead+'/read'); if(r.ok&&d.ok){ one.closest('.notif-row').classList.remove('unread'); one.remove(); if(!document.querySelector('.notif-row.unread')){const all=document.getElementById('mark-all-read'); if(all)all.hidden=true;} if(window.refreshCounters)window.refreshCounters(); } else { one.disabled=false; say(d.message||'Could not mark as read.'); } }catch(err){ one.disabled=false; say('Network error. Please try again.'); } return; }
  const all=e.target.closest('#mark-all-read');
  if(all){ all.disabled=true; try{ const {r,d}=await post('/notifications/read-all'); if(r.ok&&d.ok){ document.querySelectorAll('.notif-row.unread').forEach(x=>x.classList.remove('unread')); document.querySelectorAll('[data-mark-read]').forEach(x=>x.remove()); all.hidden=true; if(window.refreshCounters)window.refreshCounters(); say('All notifications marked as read'); } else say(d.message||'Could not mark all as read.'); }catch(err){ say('Network error. Please try again.'); } all.disabled=false; }
 });
 // Browser alerts: permission is requested ONLY after this explicit click
 const b=document.getElementById('enable-browser-alerts');
 if(b && 'Notification' in window && Notification.permission==='default'){
   b.hidden=false;
   b.addEventListener('click',async()=>{ try{ const p=await Notification.requestPermission(); b.hidden=true; say(p==='granted'?'Browser alerts enabled while this site is open in a tab':'Browser alerts blocked. In-app notifications still work.'); }catch(e){} });
 }
})();
'''


@app.route("/notifications/<int:nid>/read", methods=["POST"])
@login_required
def notification_mark_read(nid):
    conn = None
    try:
        conn = get_connection(); cur = conn.cursor()
        cur.execute("UPDATE dbo.Notifications SET IsRead=1 WHERE NotificationID=? AND UserID=?", (nid, session["user_id"]))
        if cur.rowcount == 0:
            conn.rollback()
            return jsonify(ok=False, message="Notification not found."), 404
        conn.commit()
        return jsonify(ok=True)
    except Exception:
        if conn: conn.rollback()
        app.logger.exception("Mark notification read failed")
        return jsonify(ok=False, message="Could not update the notification."), 500
    finally:
        if conn:
            conn.close()


@app.route("/notifications/read-all", methods=["POST"])
@login_required
def notifications_read_all():
    conn = None
    try:
        conn = get_connection(); cur = conn.cursor()
        cur.execute("UPDATE dbo.Notifications SET IsRead=1 WHERE UserID=? AND IsRead=0", (session["user_id"],))
        conn.commit()
        return jsonify(ok=True)
    except Exception:
        if conn: conn.rollback()
        app.logger.exception("Mark all notifications read failed")
        return jsonify(ok=False, message="Could not update notifications."), 500
    finally:
        if conn:
            conn.close()


@app.route("/notifications/<int:nid>/open")
@login_required
def notification_open(nid):
    """Mark one of the current user's notifications as read, then go to what it refers to."""
    conn = None
    try:
        conn = get_connection(); cur = conn.cursor()
        cur.execute("SELECT ActorID,NotificationType,PostID FROM dbo.Notifications WHERE NotificationID=? AND UserID=?", (nid, session["user_id"]))
        row = cur.fetchone()
        if not row:
            return redirect(url_for("notifications_page"))
        cur.execute("UPDATE dbo.Notifications SET IsRead=1 WHERE NotificationID=? AND UserID=?", (nid, session["user_id"]))
        conn.commit()
        return redirect(notification_target(str(row[1]), row[0], row[2]))
    except Exception:
        if conn: conn.rollback()
        app.logger.exception("Open notification failed")
        return redirect(url_for("notifications_page"))
    finally:
        if conn:
            conn.close()


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def home():
    conn = None
    try:
        conn = get_connection()
        cur = conn.cursor()
        posts = get_posts(cur, "WHERE 1=1", ())
        cur.execute("SELECT TOP 8 UserID,Username,FullName,ProfileImage FROM Users WHERE UserID<>? ORDER BY Username", (session["user_id"],))
        suggestions = cur.fetchall()
        follow_cols = columns(cur, "Followers")
        follower_col = pick(follow_cols, "FollowerUserID", "FollowerID", "UserID", "Follower")
        following_col = pick(follow_cols, "FollowingUserID", "FollowingID", "FollowedUserID", "Following")
        suggestion_html = []
        for user in suggestions:
            uid, uname, fullname, profile_image = user
            is_following = False
            if follower_col and following_col:
                cur.execute(f"SELECT COUNT(*) FROM Followers WHERE [{follower_col}]=? AND [{following_col}]=?", (session["user_id"], uid))
                is_following = cur.fetchone()[0] > 0
            avatar_url = safe_media_url(profile_image)
            avatar = f'<img class="avatar-small" src="{escape(avatar_url)}" alt="">' if avatar_url else '<span class="avatar-fallback">●</span>'
            suggestion_html.append(f'<div class="suggestion">{avatar}<div class="suggestion-info"><strong><a href="{url_for("user_profile",user_id=uid)}">{escape(str(uname))}</a></strong><small>{escape(str(fullname or "Suggested for you"))}</small></div><form data-ajax="follow" method="post" action="{url_for("toggle_follow",user_id=uid)}"><button type="submit" class="small-action {"secondary" if is_following else ""}">{"Following" if is_following else "Follow"}</button></form></div>')
        story_items = ['<a class="story-item" href="' + url_for("create_post") + '"><div class="story-ring"><div class="story-inner">+</div></div>Your story</a>']
        for su in suggestions[:12]:
            sid, sname, sfull, simage = su
            simage_url = safe_media_url(simage)
            inner = f'<img src="{escape(simage_url)}" alt="">' if simage_url else escape((str(sname or "U")[:1]).upper())
            story_items.append(f'<a class="story-item" href="{url_for("user_profile", user_id=sid)}"><div class="story-ring"><div class="story-inner">{inner}</div></div>{escape(str(sname))}</a>')
        stories_html = '<div class="stories-strip" aria-label="Stories">' + ''.join(story_items) + '</div>'
        content = '<div class="container"><div class="feed-layout"><section class="feed-column">' + stories_html + render_posts(posts, session["user_id"]) + '</section><aside class="right-sidebar"><div class="suggestion-title"><span>Suggested for you</span><a href="' + url_for("search_users") + '">See all</a></div>' + (''.join(suggestion_html) or '<p class="muted">No suggestions available yet.</p>') + '<div class="footer-note">About · Help · Privacy · Terms<br>© 2026 InstaClone</div></aside></div></div>'
        return render_template_string(PAGE, title="Home", content=content)
    except Exception:
        app.logger.exception("Home feed failed")
        return "The home feed could not be loaded. Please try again.", 500
    finally:
        if conn:
            conn.close()


@app.route("/post/<int:post_id>")
@login_required
def view_post(post_id):
    """Single post view: target of like/comment notifications for photo posts."""
    conn = None
    try:
        conn = get_connection(); cur = conn.cursor()
        posts = get_posts(cur, "WHERE p.PostID=?", (post_id,))
        if not posts:
            abort(404)
        content = '<div class="container">' + render_posts(posts, session["user_id"]) + '</div>'
        return render_template_string(PAGE, title="Post", content=content)
    except HTTPException:
        raise
    except Exception:
        app.logger.exception("Post view failed")
        return "The post could not be loaded. Please try again.", 500
    finally:
        if conn:
            conn.close()


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username=request.form.get("username", "").strip(); full_name=request.form.get("full_name", "").strip(); email=request.form.get("email", "").strip().lower(); password=request.form.get("password", "")
        if not all([username, full_name, email, password]): flash("Please complete every field."); return redirect(url_for("signup"))
        if len(username)>50 or len(full_name)>100 or len(email)>255 or len(password)<8: flash("Check the username, name, and email lengths. Password must be at least 8 characters."); return redirect(url_for("signup"))
        conn=None
        try:
            conn=get_connection(); cur=conn.cursor(); cur.execute("SELECT Username,Email FROM Users WHERE Username=? OR Email=?",(username,email)); old=cur.fetchone()
            if old: flash("That username or email is already registered."); return redirect(url_for("signup"))
            cur.execute("INSERT INTO Users (Username,Email,PasswordHash,FullName) VALUES (?,?,?,?)",(username,email,generate_password_hash(password),full_name)); conn.commit(); flash("Account created successfully. Please log in."); return redirect(url_for("login"))
        except Exception:
            if conn: conn.rollback()
            app.logger.exception("Signup failed"); flash("Sign-up failed. Please try again."); return redirect(url_for("signup"))
        finally:
            if conn: conn.close()
    content='''<div class="card"><h1>Create account</h1><form method="post"><label>Full name</label><input name="full_name" maxlength="100" required><label>Username</label><input name="username" maxlength="50" required><label>Email</label><input type="email" name="email" maxlength="255" required><label>Password (8+ characters)</label><input type="password" name="password" minlength="8" required><button>Sign up</button></form><p>Already have account? <a href="/login">Login</a></p></div>'''
    return render_template_string(PAGE,title="Sign up",content=content)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username=request.form.get("username", "").strip(); password=request.form.get("password", ""); conn=None
        try:
            conn=get_connection(); cur=conn.cursor(); cur.execute("SELECT UserID,Username,PasswordHash FROM Users WHERE Username=?",(username,)); user=cur.fetchone()
            if user and check_password_hash(user[2],password): session.clear(); session["user_id"]=user[0]; session["username"]=user[1]; return redirect(url_for("home"))
            flash("Incorrect username or password."); return redirect(url_for("login"))
        except Exception:
            app.logger.exception("Login failed"); flash("Login failed. Please try again."); return redirect(url_for("login"))
        finally:
            if conn: conn.close()
    content='''<div class="card"><h1>Login</h1><form method="post"><label>Username</label><input name="username" required><label>Password</label><input type="password" name="password" required><button>Login</button></form><p>New user? <a href="/signup">Sign up</a></p></div>'''
    return render_template_string(PAGE,title="Login",content=content)


@app.route("/logout")
def logout():
    session.clear(); flash("You have been logged out."); return redirect(url_for("login"))


@app.route("/profile")
@login_required
def profile():
    return redirect(url_for("user_profile", user_id=session["user_id"]))


@app.route("/u/<int:user_id>")
@login_required
def user_profile(user_id):
    conn=None
    try:
        conn=get_connection(); cur=conn.cursor(); cur.execute("SELECT UserID,Username,FullName,Bio,ProfileImage FROM Users WHERE UserID=?",(user_id,)); user=cur.fetchone()
        if not user: abort(404)
        cur.execute("SELECT COUNT(*) FROM Posts WHERE UserID=?",(user_id,)); post_count=cur.fetchone()[0]
        f=columns(cur,"Followers"); follower_col=pick(f,"FollowerUserID","FollowerID","UserID","Follower"); following_col=pick(f,"FollowingUserID","FollowingID","FollowedUserID","Following")
        followers=following=0; is_following=False
        if follower_col and following_col:
            cur.execute(f"SELECT COUNT(*) FROM Followers WHERE [{following_col}]=?",(user_id,)); followers=cur.fetchone()[0]
            cur.execute(f"SELECT COUNT(*) FROM Followers WHERE [{follower_col}]=?",(user_id,)); following=cur.fetchone()[0]
            cur.execute(f"SELECT COUNT(*) FROM Followers WHERE [{follower_col}]=? AND [{following_col}]=?",(session["user_id"],user_id)); is_following=cur.fetchone()[0]>0
        cur.execute("SELECT PostID,UserID,Caption,MediaPath,MediaType,CreatedAt, (SELECT Username FROM Users WHERE UserID=Posts.UserID), (SELECT ProfileImage FROM Users WHERE UserID=Posts.UserID) FROM Posts WHERE UserID=? ORDER BY CreatedAt DESC,PostID DESC",(user_id,)); posts=cur.fetchall()
        avatar=safe_media_url(user[4]); own=user_id==session["user_id"]
        grid=[]
        for p in posts:
            u=safe_media_url(p[3]);
            if not u: continue
            if p[4]=="video": grid.append(f'<a class="tile" href="{url_for("reels", post_id=p[0])}"><video src="{escape(u)}" muted preload="metadata"></video></a>')
            else: grid.append(f'<a class="tile" href="{url_for("view_post", post_id=p[0])}"><img src="{escape(u)}" alt="Post"></a>')
        if own: action='<a class="btn secondary" href="/edit-profile">Edit Profile</a> <a class="btn" href="/create-post">Create Post</a>'
        elif is_following: action=f'<form data-ajax="follow" method="post" action="{url_for("toggle_follow",user_id=user_id)}"><button type="submit" class="secondary">Following</button></form> <a class="btn" style="background:#000;border:1px solid #444" href="{url_for("messages_page",user_id=user_id)}">Message</a>'
        else: action=f'<form data-ajax="follow" method="post" action="{url_for("toggle_follow",user_id=user_id)}"><button type="submit">Follow</button></form> <a class="btn" style="background:#000;border:1px solid #444" href="{url_for("messages_page",user_id=user_id)}">Message</a>'
        content=f'''<div class="container"><section class="profile"><div>{f'<img class="avatar" src="{escape(avatar)}" alt="Profile">' if avatar else '<div class="avatar-placeholder">👤</div>'}</div><div><h1>{escape(str(user[1]))}</h1><div class="stats"><span><strong>{post_count}</strong> posts</span><span><strong data-followers-count>{followers}</strong> followers</span><span><strong>{following}</strong> following</span></div><h3>{escape(str(user[2] or user[1]))}</h3><p>{escape(str(user[3] or ''))}</p><div class="actions">{action}</div></div></section><div class="tabs"><a class="active" href="{url_for('user_profile',user_id=user_id)}">POSTS</a><a href="{url_for('reels',user_id=user_id)}">REELS</a></div><div class="grid">{''.join(grid) or '<div class="empty">No posts yet.</div>'}</div></div>'''
        return render_template_string(PAGE,title="Profile",content=content)
    except HTTPException:
        raise
    except Exception:
        app.logger.exception("Profile page failed"); return "The profile could not be loaded. Please check the application log.",500
    finally:
        if conn: conn.close()


@app.route("/edit-profile", methods=["GET","POST"])
@login_required
def edit_profile():
    conn=None; new_file=None
    try:
        conn=get_connection(); cur=conn.cursor(); cur.execute("SELECT FullName,Bio,ProfileImage FROM Users WHERE UserID=?",(session["user_id"],)); user=cur.fetchone()
        if not user: session.clear(); return redirect(url_for("login"))
        if request.method=="POST":
            name=request.form.get("full_name","").strip(); bio=request.form.get("bio","").strip(); image=request.files.get("profile_image")
            if not name or len(name)>100 or len(bio)>500: flash("Name required; bio max 500 characters."); return redirect(url_for("edit_profile"))
            if image and image.filename: new_file,kind=save_media(image); 
            if new_file and kind!="image": raise ValueError("Profile picture must be an image, not a video.")
            if new_file: cur.execute("UPDATE Users SET FullName=?,Bio=?,ProfileImage=? WHERE UserID=?",(name,bio,new_file,session["user_id"]))
            else: cur.execute("UPDATE Users SET FullName=?,Bio=? WHERE UserID=?",(name,bio,session["user_id"]))
            conn.commit(); flash("Profile updated successfully."); return redirect(url_for("profile"))
        avatar=safe_media_url(user[2]); content=f'''<div class="card"><h1>Edit Profile</h1>{f'<img class="avatar" src="{escape(avatar)}">' if avatar else ''}<form method="post" enctype="multipart/form-data"><label>Full name</label><input name="full_name" maxlength="100" value="{escape(str(user[0] or ''))}" required><label>Bio</label><textarea name="bio" maxlength="500">{escape(str(user[1] or ''))}</textarea><label>Profile photo (max 5 MB)</label><input type="file" name="profile_image" accept=".jpg,.jpeg,.png,.webp"><button>Save Changes</button></form></div>'''
        return render_template_string(PAGE,title="Edit Profile",content=content)
    except ValueError as e:
        if new_file:
            try: os.remove(os.path.join(UPLOAD_FOLDER,new_file))
            except OSError: pass
        flash(str(e)); return redirect(url_for("edit_profile"))
    except Exception:
        if conn: conn.rollback()
        app.logger.exception("Edit profile failed"); return "Edit profile fail hua. Terminal check karein.",500
    finally:
        if conn: conn.close()


@app.route("/create-post", methods=["GET","POST"])
@login_required
def create_post():
    conn=None; filename=None
    if request.method=="POST":
        caption=request.form.get("caption","").strip()
        if len(caption)>2000: flash("Caption must be 2,000 characters or fewer."); return redirect(url_for("create_post"))
        try:
            filename,kind=save_media(request.files.get("media")); conn=get_connection(); cur=conn.cursor()
            cur.execute("INSERT INTO Posts (UserID,Caption,MediaPath,MediaType) VALUES (?,?,?,?)",(session["user_id"],caption,filename,kind)); conn.commit(); flash("Post published successfully!"); return redirect(url_for("profile"))
        except ValueError as e:
            if filename:
                try: os.remove(os.path.join(UPLOAD_FOLDER,filename))
                except OSError: pass
            flash(str(e)); return redirect(url_for("create_post"))
        except Exception:
            if conn: conn.rollback()
            if filename:
                try: os.remove(os.path.join(UPLOAD_FOLDER,filename))
                except OSError: pass
            app.logger.exception("Post upload failed"); return "Post upload failed. Please try again.",500
        finally:
            if conn: conn.close()
    content='''<div class="card"><h1>Create Post / Reel</h1><p class="muted">Photo max 5 MB; video max 50 MB. Supported: JPG, PNG, WebP, MP4, WebM, MOV.</p><form method="post" enctype="multipart/form-data"><label>Photo or video</label><input type="file" name="media" accept=".jpg,.jpeg,.png,.webp,.mp4,.webm,.mov,image/jpeg,image/png,image/webp,video/mp4,video/webm,video/quicktime" required><label>Caption</label><textarea name="caption" maxlength="2000" placeholder="Write a caption..."></textarea><button>Share</button></form></div>'''
    return render_template_string(PAGE,title="Create Post",content=content)


@app.route("/reels")
@login_required
def reels():
    conn=None
    try:
        conn=get_connection(); cur=conn.cursor(); user_id=request.args.get("user_id",type=int); post_id=request.args.get("post_id",type=int)
        sql="WHERE p.MediaType='video'"; params=[]
        if user_id: sql += " AND p.UserID=?"; params.append(user_id)
        if post_id: sql += " AND p.PostID=?"; params.append(post_id)
        posts=get_posts(cur,sql,tuple(params)); cards=[]
        for p in posts:
            pid, owner_id, caption, path, media_type, created, username, profile_image=p
            media=safe_media_url(path)
            if not media: continue
            liked, count=like_state(cur,pid,session['user_id']); comments=comment_rows(cur,pid)
            saved=saved_state(cur,pid,session['user_id'])
            avatar_url=safe_media_url(profile_image)
            avatar=f'<img src="{escape(avatar_url)}" alt="" class="reel-avatar">' if avatar_url else f'<span class="reel-avatar" style="display:grid;place-items:center">{escape(str(username or "U")[:1].upper())}</span>'
            follow=''
            if int(owner_id)!=int(session['user_id']):
                fcols=columns(cur,'Followers'); fc=pick(fcols,'FollowerUserID','FollowerID','UserID','Follower'); gc=pick(fcols,'FollowingUserID','FollowingID','FollowedUserID','Following')
                following=False
                if fc and gc:
                    cur.execute(f"SELECT COUNT(*) FROM Followers WHERE [{fc}]=? AND [{gc}]=?",(session['user_id'],owner_id)); following=cur.fetchone()[0]>0
                follow=f'<form data-ajax="follow" method="post" action="{url_for("toggle_follow",user_id=owner_id)}"><button class="reel-follow" type="submit">{"Following" if following else "Follow"}</button></form>'
            cards.append(f"""<div class="reel-item"><article class="reels-stage" data-reel-card data-post-id="{pid}"><video src="{escape(media)}" controls playsinline preload="metadata" loop></video><div class="reel-overlay"><div class="reel-creator">{avatar}<strong>@{escape(str(username or 'user'))}</strong>{follow}</div><p class="reel-caption">{escape(str(caption or ''))}</p><div class="reel-audio">♫ Original audio · @{escape(str(username or 'user'))}</div><div class="muted">{escape(str(created or ''))}</div><form class="reel-comment" data-ajax="comment" method="post" action="{url_for('add_comment',post_id=pid)}" hidden><input name="comment" maxlength="1000" placeholder="Add a comment..." aria-label="Add a comment" required><button type="submit">Post</button></form></div></article><aside class="reel-toolbar"><form data-ajax="like" method="post" action="{url_for('toggle_like',post_id=pid)}" class="reel-tool"><button type="submit" class="{'liked' if liked else ''}" aria-label="Like Reel">{'♥' if liked else '♡'}</button><small data-like-count>{count}</small></form><button type="button" class="reel-tool" data-toggle-reel-comment aria-label="Comment on Reel">▢<small data-comment-count>{len(comments)}</small></button><button class="reel-tool" type="button" aria-label="Share Reel" onclick="navigator.clipboard?.writeText(location.origin+'{url_for('reels',post_id=pid)}');document.getElementById('toast').textContent='Reel link copied';document.getElementById('toast').hidden=false">➤<small>Share</small></button><form data-ajax="save" method="post" action="{url_for('toggle_save',post_id=pid)}" class="reel-tool"><button type="submit" class="{'saved' if saved else ''}" aria-label="Save Reel">{'▣' if saved else '▱'}</button><small>Save</small></form></aside></div>""")
        if not cards: content='<div class="reels-page"><div class="reel-empty"><h2>No Reels yet</h2><p>Videos you upload will appear here.</p><a class="btn" href="/create-post">Upload your first Reel</a></div></div>'
        else:
            content='<div class="reels-page" id="reels-page">'+''.join(cards)+'<div class="reel-arrows"><button class="reel-arrow" type="button" id="reel-prev" aria-label="Previous Reel">⌃</button><button class="reel-arrow" type="button" id="reel-next" aria-label="Next Reel">⌄</button></div></div><script>(function(){const cards=[...document.querySelectorAll("[data-reel-card]")];let i=Math.max(0,cards.findIndex(c=>c.dataset.postId==="'+str(post_id or '')+'"));function go(d){if(!cards.length)return;i=Math.max(0,Math.min(cards.length-1,i+d));cards[i].scrollIntoView({behavior:"smooth",block:"center"});const v=cards[i].querySelector("video");if(v)v.play().catch(()=>{});}document.getElementById("reel-prev")?.addEventListener("click",()=>go(-1));document.getElementById("reel-next")?.addEventListener("click",()=>go(1));document.addEventListener("keydown",e=>{if(e.target&&/INPUT|TEXTAREA/.test(e.target.tagName))return;if(e.key==="ArrowDown")go(1);if(e.key==="ArrowUp")go(-1)});let wheelLock=false;document.getElementById("reels-page")?.addEventListener("wheel",e=>{if(wheelLock)return;wheelLock=true;go(e.deltaY>0?1:-1);setTimeout(()=>wheelLock=false,500)},{passive:true});})();</script>'
        return render_template_string(PAGE,title="Reels",content=content)
    except Exception:
        app.logger.exception("Reels failed"); return "Reels could not be loaded. Please try again.",500
    finally:
        if conn: conn.close()


# ---------------------------------------------------------------------------
# Likes / comments / follows / saves (AJAX-aware, notifications in the same transaction)
# ---------------------------------------------------------------------------
@app.route("/like/<int:post_id>",methods=["POST"])
@login_required
def toggle_like(post_id):
    me=int(session["user_id"]); conn=None
    try:
        conn=get_connection(); cur=conn.cursor(); cur.execute("SELECT UserID,MediaType FROM Posts WHERE PostID=?",(post_id,)); post=cur.fetchone()
        if not post: return fail("Post not found.",404)
        c=columns(cur,"Likes"); post_col=pick(c,"PostID","PostId","Post_ID"); user_col=pick(c,"UserID","LikerUserID","LikedByUserID","User_ID")
        if not post_col or not user_col: raise RuntimeError("Could not identify the PostID and UserID columns in Likes.")
        # UPDLOCK+HOLDLOCK serialises double-clicks so only one like row per user/post can be created
        cur.execute(f"SELECT COUNT(*) FROM Likes WITH (UPDLOCK, HOLDLOCK) WHERE [{post_col}]=? AND [{user_col}]=?",(post_id,me))
        if cur.fetchone()[0]:
            cur.execute(f"DELETE FROM Likes WHERE [{post_col}]=? AND [{user_col}]=?",(post_id,me))
        else:
            insert_dynamic(cur,"Likes",[(("PostID","PostId","Post_ID"),post_id),(("UserID","LikerUserID","LikedByUserID","User_ID"),me)])
            create_notification(cur,post[0],me,"reel_like" if str(post[1]).lower()=="video" else "post_like",post_id)
        cur.execute(f"SELECT COUNT(*) FROM Likes WHERE [{post_col}]=? AND [{user_col}]=?", (post_id, me))
        liked = cur.fetchone()[0] > 0
        cur.execute(f"SELECT COUNT(*) FROM Likes WHERE [{post_col}]=?", (post_id,))
        count = cur.fetchone()[0]
        conn.commit()
        if is_ajax():
            return jsonify(ok=True, liked=liked, count=count)
    except Exception:
        if conn: conn.rollback()
        app.logger.exception("Like action failed")
        return fail("Like could not be saved. Please try again.",500)
    finally:
        if conn: conn.close()
    return redirect(request.referrer or url_for("home"))


@app.route("/comment/<int:post_id>",methods=["POST"])
@login_required
def add_comment(post_id):
    me=int(session["user_id"]); text=request.form.get("comment","").strip(); conn=None
    if not text or len(text)>1000:
        return fail("Comments must contain between 1 and 1,000 characters.",400)
    try:
        conn=get_connection(); cur=conn.cursor(); cur.execute("SELECT UserID,MediaType FROM Posts WHERE PostID=?",(post_id,)); post=cur.fetchone()
        if not post: return fail("Post not found.",404)
        insert_dynamic(cur,"Comments",[(("PostID","PostId","Post_ID"),post_id),(("UserID","CommenterUserID","CreatedByUserID","User_ID"),me),(("CommentText","Comment","Content","Text","Body"),text),(("CreatedAt","CommentDate","CreatedOn"),datetime.now())])
        create_notification(cur,post[0],me,"reel_comment" if str(post[1]).lower()=="video" else "comment",post_id)
        cur.execute("SELECT Username FROM Users WHERE UserID=?", (me,))
        username = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM Comments WHERE PostID=?", (post_id,))
        comment_count = cur.fetchone()[0]
        conn.commit()
        if is_ajax():
            return jsonify(ok=True, username=username, comment=text, comment_count=comment_count)
    except Exception:
        if conn: conn.rollback()
        app.logger.exception("Comment failed")
        return fail("Comment could not be saved. Please try again.",500)
    finally:
        if conn: conn.close()
    return redirect(request.referrer or url_for("home"))


@app.route("/follow/<int:user_id>",methods=["POST"])
@login_required
def toggle_follow(user_id):
    me=int(session["user_id"])
    if user_id==me: return fail("You cannot follow your own account.",400,url_for("profile"))
    conn=None
    try:
        conn=get_connection(); cur=conn.cursor(); cur.execute("SELECT UserID FROM Users WHERE UserID=?",(user_id,))
        if not cur.fetchone(): return fail("User not found.",404)
        c=columns(cur,"Followers"); follower=pick(c,"FollowerUserID","FollowerID","UserID","Follower"); following=pick(c,"FollowingUserID","FollowingID","FollowedUserID","Following")
        if not follower or not following: raise RuntimeError("Could not identify user ID columns in Followers.")
        cur.execute(f"SELECT COUNT(*) FROM Followers WITH (UPDLOCK, HOLDLOCK) WHERE [{follower}]=? AND [{following}]=?",(me,user_id))
        if cur.fetchone()[0]: cur.execute(f"DELETE FROM Followers WHERE [{follower}]=? AND [{following}]=?",(me,user_id))
        else:
            insert_dynamic(cur,"Followers",[(("FollowerUserID","FollowerID","UserID","Follower"),me),(("FollowingUserID","FollowingID","FollowedUserID","Following"),user_id)])
            create_notification(cur,user_id,me,"follow")
        cur.execute(f"SELECT COUNT(*) FROM Followers WHERE [{follower}]=? AND [{following}]=?", (me, user_id))
        is_following = cur.fetchone()[0] > 0
        cur.execute(f"SELECT COUNT(*) FROM Followers WHERE [{following}]=?", (user_id,))
        followers = cur.fetchone()[0]
        conn.commit()
        if is_ajax():
            return jsonify(ok=True, following=is_following, followers=followers)
    except Exception:
        if conn: conn.rollback()
        app.logger.exception("Follow action failed")
        return fail("Follow status could not be updated. Please try again.",500,url_for("user_profile",user_id=user_id))
    finally:
        if conn: conn.close()
    return redirect(url_for("user_profile",user_id=user_id))


@app.route("/save/<int:post_id>", methods=["POST"])
@login_required
def toggle_save(post_id):
    conn = None
    try:
        conn = get_connection(); cur = conn.cursor(); ensure_saved_posts_table(cur)
        cur.execute("SELECT PostID FROM Posts WHERE PostID=?", (post_id,))
        if not cur.fetchone(): return fail("Post not found.",404)
        cur.execute("SELECT COUNT(*) FROM dbo.SavedPosts WITH (UPDLOCK, HOLDLOCK) WHERE UserID=? AND PostID=?", (session["user_id"], post_id))
        if cur.fetchone()[0]:
            cur.execute("DELETE FROM dbo.SavedPosts WHERE UserID=? AND PostID=?", (session["user_id"], post_id)); saved = False
        else:
            cur.execute("INSERT INTO dbo.SavedPosts (UserID,PostID) VALUES (?,?)", (session["user_id"], post_id)); saved = True
        conn.commit()
        if is_ajax(): return jsonify(ok=True, saved=saved)
    except Exception:
        if conn: conn.rollback()
        app.logger.exception("Save post failed")
        return fail("Post could not be saved. Please try again.",500)
    finally:
        if conn: conn.close()
    return redirect(request.referrer or url_for("home"))


@app.route("/saved")
@login_required
def saved_posts():
    conn = None
    try:
        conn = get_connection(); cur = conn.cursor(); ensure_saved_posts_table(cur); conn.commit()
        posts = get_posts(cur, "JOIN dbo.SavedPosts s ON s.PostID=p.PostID WHERE s.UserID=?", (session["user_id"],))
        content = '<div class="container"><h2>Saved posts</h2>' + render_posts(posts, session["user_id"]) + '</div>'
        return render_template_string(PAGE, title="Saved", content=content)
    except Exception:
        app.logger.exception("Saved posts failed"); return "Saved posts could not be loaded. Please try again.", 500
    finally:
        if conn: conn.close()


@app.route("/explore")
@login_required
def explore():
    return redirect(url_for("home"))


# ---------------------------------------------------------------------------
# Direct messaging
# ---------------------------------------------------------------------------
def get_conversations(cur, uid):
    """One row per person the user has exchanged messages with: last message + unread count."""
    cur.execute("""
        WITH c AS (
            SELECT CASE WHEN SenderID=? THEN ReceiverID ELSE SenderID END AS OtherID,
                   MessageID, MessageText, SentAt, SenderID,
                   ROW_NUMBER() OVER (PARTITION BY CASE WHEN SenderID=? THEN ReceiverID ELSE SenderID END ORDER BY MessageID DESC) AS rn
            FROM dbo.Messages WHERE SenderID=? OR ReceiverID=?
        )
        SELECT u.UserID,u.Username,u.FullName,u.ProfileImage,c.MessageText,c.SentAt,c.SenderID,
               (SELECT COUNT(*) FROM dbo.Messages m WHERE m.SenderID=u.UserID AND m.ReceiverID=? AND m.IsRead=0) AS Unread
        FROM c JOIN dbo.Users u ON u.UserID=c.OtherID
        WHERE c.rn=1 ORDER BY c.MessageID DESC
    """, (uid, uid, uid, uid, uid))
    out = []
    for r in cur.fetchall():
        out.append({"id": int(r[0]), "username": r[1], "full_name": r[2], "profile": r[3],
                    "text": str(r[4] or ""), "sent_at": r[5], "sender_id": int(r[6]), "unread": int(r[7] or 0)})
    return out


def snippet_for(conv, uid):
    text = conv["text"].replace("\n", " ").strip()
    if len(text) > 45:
        text = text[:45] + "…"
    return ("You: " if conv["sender_id"] == uid else "") + text


def conv_row_html(person, snippet, when, unread, selected):
    pid, username, full_name, profile = person[0], person[1], person[2], person[3]
    pill = f'<span class="unread-pill">{int(unread)}</span>' if unread else ""
    cls = "conversation-row" + (" selected" if selected else "") + (" unread" if unread else "")
    return (f'<a class="{cls}" href="{url_for("messages_page", user_id=pid)}" aria-label="Open conversation with {escape(str(username))}">'
            f'{avatar_html(profile, username)}<div class="conversation-copy"><strong>{escape(str(full_name or username))}</strong>'
            f'<span>{escape(snippet)}</span></div><div class="conversation-meta"><span class="conversation-time">{escape(when)}</span>{pill}</div></a>')


def inbox_list_html(cur, uid, selected, query=""):
    """Left-hand conversation list: real conversations from SQL Server, plus people search for new chats."""
    q = (query or "").strip()
    ql = q.lower()
    convs = get_conversations(cur, uid)
    sel_id = int(selected[0]) if selected else None
    rows = []
    shown = set()
    if selected and not any(c["id"] == sel_id for c in convs):
        rows.append(conv_row_html(selected, "Start a conversation", "", 0, True)); shown.add(sel_id)
    for c in convs:
        if ql and ql not in str(c["username"] or "").lower() and ql not in str(c["full_name"] or "").lower():
            continue
        rows.append(conv_row_html((c["id"], c["username"], c["full_name"], c["profile"]), snippet_for(c, uid), short_time(c["sent_at"]), c["unread"], c["id"] == sel_id))
        shown.add(c["id"])
    if q:
        cur.execute("SELECT TOP 20 UserID,Username,FullName,ProfileImage FROM Users WHERE UserID<>? AND (Username LIKE ? OR FullName LIKE ?) ORDER BY Username", (uid, "%" + q + "%", "%" + q + "%"))
        extra = [u for u in cur.fetchall() if int(u[0]) not in shown]
        if extra:
            rows.append('<div class="list-heading">People</div>')
            for u in extra:
                rows.append(conv_row_html(u, "Start a conversation", "", 0, sel_id == int(u[0])))
    return "".join(rows) or '<div class="messages-panel-empty">No conversations yet.<br>Search for someone or use the ✎ button to start one.</div>'


@app.route("/messages/preview")
@login_required
def messages_preview():
    me = int(session["user_id"]); conn = None
    try:
        conn = get_connection(); cur = conn.cursor()
        users = []
        for c in get_conversations(cur, me)[:12]:
            name = str(c["full_name"] or c["username"] or "user")
            users.append({"id": c["id"], "username": str(c["username"] or "user"), "name": name, "initial": (name[:1] or "U").upper(),
                          "avatar": safe_media_url(c["profile"]) or "", "snippet": snippet_for(c, me), "time": short_time(c["sent_at"]), "unread": c["unread"]})
        if not users:
            for row in followed_people(cur, me, 12):
                username = str(row[1] or "user"); full_name = str(row[2] or username)
                users.append({"id": int(row[0]), "username": username, "name": full_name, "initial": (full_name[:1] or "U").upper(),
                              "avatar": safe_media_url(row[3]) or "", "snippet": "Start a conversation", "time": "", "unread": 0})
        return jsonify(users=users)
    except Exception:
        app.logger.exception("Messages preview failed"); return jsonify(users=[]), 500
    finally:
        if conn: conn.close()


@app.route("/messages/conversations")
@login_required
def messages_conversations():
    me = int(session["user_id"]); conn = None
    try:
        conn = get_connection(); cur = conn.cursor()
        sel_id = request.args.get("user_id", type=int)
        selected = get_user_brief(cur, sel_id) if sel_id and sel_id != me else None
        return jsonify(ok=True, html=inbox_list_html(cur, me, selected, request.args.get("q", "")))
    except Exception:
        app.logger.exception("Conversation list failed"); return jsonify(ok=False, html=""), 500
    finally:
        if conn: conn.close()


@app.route("/messages/history")
@login_required
def messages_history():
    """Messages between the logged-in user and ?user_id=. Both sides of the pair always include the session user,
    so nobody can read a conversation they are not part of. Opening it marks incoming messages as read."""
    me = int(session["user_id"])
    other = request.args.get("user_id", type=int)
    after = request.args.get("after_id", 0, type=int) or 0
    if not other or other == me:
        return jsonify(ok=False, messages=[], message="Invalid conversation."), 400
    conn = None
    try:
        conn = get_connection(); cur = conn.cursor()
        cur.execute("SELECT UserID FROM Users WHERE UserID=?", (other,))
        if not cur.fetchone():
            return jsonify(ok=False, messages=[], message="User not found."), 404
        cur.execute("""SELECT TOP 300 MessageID,SenderID,MessageText,SentAt FROM dbo.Messages
                       WHERE MessageID>? AND ((SenderID=? AND ReceiverID=?) OR (SenderID=? AND ReceiverID=?))
                       ORDER BY MessageID DESC""", (after, me, other, other, me))
        rows = list(reversed(cur.fetchall()))
        max_incoming = max([int(r[0]) for r in rows if int(r[1]) == other], default=0)
        if max_incoming:
            cur.execute("UPDATE dbo.Messages SET IsRead=1 WHERE SenderID=? AND ReceiverID=? AND IsRead=0 AND MessageID<=?", (other, me, max_incoming))
            cur.execute("UPDATE dbo.Notifications SET IsRead=1 WHERE UserID=? AND ActorID=? AND NotificationType='message' AND IsRead=0", (me, other))
        conn.commit()
        return jsonify(ok=True, messages=[{"id": int(r[0]), "sender_id": int(r[1]), "mine": int(r[1]) == me, "text": str(r[2] or ""), "sent_at": iso(r[3])} for r in rows])
    except Exception:
        if conn: conn.rollback()
        app.logger.exception("Message history failed")
        return jsonify(ok=False, messages=[], message="Message history could not be loaded."), 500
    finally:
        if conn: conn.close()


@app.route("/messages/send", methods=["POST"])
@login_required
def messages_send():
    me = int(session["user_id"])  # the sender is ALWAYS the logged-in user, never a client-supplied value
    other = request.form.get("receiver_id", type=int)
    message = (request.form.get("message") or "").replace("\r\n", "\n").strip()
    if not other or other == me:
        return jsonify(ok=False, message="Choose a valid recipient."), 400
    if not message or len(message) > 2000:
        return jsonify(ok=False, message="Enter a message of 1 to 2,000 characters."), 400
    conn = None
    try:
        conn = get_connection(); cur = conn.cursor()
        cur.execute("SELECT UserID FROM Users WHERE UserID=?", (other,))
        if not cur.fetchone():
            return jsonify(ok=False, message="Recipient not found."), 404
        # Idempotency: an identical message from the same sender within 2 seconds is treated as a duplicate request
        cur.execute("SELECT TOP 1 MessageID FROM dbo.Messages WHERE SenderID=? AND ReceiverID=? AND MessageText=? AND SentAt>DATEADD(second,-2,SYSDATETIME()) ORDER BY MessageID DESC", (me, other, message))
        if cur.fetchone():
            return jsonify(ok=True, duplicate=True)
        cur.execute("INSERT INTO dbo.Messages(SenderID,ReceiverID,MessageText,SentAt,IsRead) VALUES(?,?,?,SYSDATETIME(),0)", (me, other, message))
        create_notification(cur, other, me, "message")
        conn.commit()
        return jsonify(ok=True)
    except Exception:
        if conn: conn.rollback()
        app.logger.exception("Message send failed")
        return jsonify(ok=False, message="Message could not be saved. Please try again."), 500
    finally:
        if conn: conn.close()


CHAT_JS = r'''
(function(){
 const me=__ME__, other=__OTHER__;
 const scroll=document.getElementById('chat-scroll'), form=document.getElementById('chat-composer'), input=document.getElementById('chat-message'), list=document.querySelector('.conversation-list');
 let lastId=0, sending=false, loading=false, firstLoadDone=false, lastListHtml=null;
 const say=m=>{ if(window.toast) window.toast(m); };
 const fmt=iso=>{ const d=new Date(iso); if(isNaN(d)) return ''; const now=new Date(); const t=d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}); return d.toDateString()===now.toDateString()? t : d.toLocaleDateString([], {month:'short',day:'numeric'})+' '+t; };
 function addBubble(m){
   const empty=document.getElementById('chat-empty'); if(empty) empty.remove();
   if(scroll.querySelector('[data-mid="'+m.id+'"]')) return;
   const b=document.createElement('div'); b.className='chat-bubble'+(m.mine?' outgoing':''); b.dataset.mid=m.id;
   const t=document.createElement('div'); t.className='chat-text'; t.textContent=m.text;
   const s=document.createElement('small'); s.className='chat-time'; s.textContent=fmt(m.sent_at);
   b.append(t,s); scroll.appendChild(b); lastId=Math.max(lastId,m.id);
 }
 async function refreshList(){
   if(!list) return;
   try{
     const q=new URLSearchParams(location.search).get('q')||'';
     const r=await fetch('/messages/conversations?user_id='+(other||'')+'&q='+encodeURIComponent(q),{credentials:'same-origin',headers:{'Accept':'application/json'}});
     const d=await r.json();
     if(d.ok && d.html!==lastListHtml){ lastListHtml=d.html; list.innerHTML=d.html; }
   }catch(e){}
 }
 async function loadHistory(force){
   if(!other||!scroll) return;
   if(loading && !force) return;
   loading=true;
   try{
     const r=await fetch('/messages/history?user_id='+other+'&after_id='+lastId,{credentials:'same-origin',headers:{'Accept':'application/json'}});
     const d=await r.json();
     if(!r.ok||d.ok===false) throw new Error(d.message||'Unable to load messages');
     const nearBottom=scroll.scrollHeight-scroll.scrollTop-scroll.clientHeight<120;
     d.messages.forEach(addBubble);
     if(d.messages.length && (force||!firstLoadDone||nearBottom)) scroll.scrollTop=scroll.scrollHeight;
     if(d.messages.length){ refreshList(); if(window.refreshCounters) window.refreshCounters(); }
     firstLoadDone=true;
   }catch(e){ if(!firstLoadDone){ say(e.message||'Unable to load messages'); firstLoadDone=true; } }
   finally{ loading=false; }
 }
 async function send(){
   if(sending||!other||!input) return;
   const value=input.value.trim(); if(!value) return;
   sending=true;
   const btn=form.querySelector('button[type=submit]'); btn.disabled=true;
   try{
     const data=new FormData(); data.append('receiver_id',other); data.append('message',value);
     const r=await fetch('/messages/send',{method:'POST',body:data,credentials:'same-origin',headers:{'X-Requested-With':'XMLHttpRequest','X-CSRFToken':window.CSRF,'Accept':'application/json'}});
     let d={}; try{ d=await r.json(); }catch(e){}
     if(!r.ok||!d.ok) throw new Error(d.message||'Message failed to send.');
     input.value=''; input.style.height='38px';
     await loadHistory(true); refreshList();
   }catch(err){ say((err&&err.message)?err.message+' Your text was kept.':'Network error. Your text was kept - try again.'); }
   finally{ sending=false; btn.disabled=false; input.focus(); }
 }
 if(form){
   form.addEventListener('submit',e=>{ e.preventDefault(); send(); });
   input.addEventListener('keydown',e=>{ if(e.key==='Enter' && !e.shiftKey && !e.isComposing){ e.preventDefault(); send(); } });
   input.addEventListener('input',()=>{ input.style.height='38px'; input.style.height=Math.min(input.scrollHeight,120)+'px'; });
 }
 if(other){ loadHistory(true); setInterval(()=>{ if(!document.hidden) loadHistory(false); },3000); }
 refreshList(); setInterval(()=>{ if(!document.hidden) refreshList(); },8000);
 if(new URLSearchParams(location.search).get('compose')==='1'){ const s=document.getElementById('inbox-search-input'); if(s) s.focus(); }
})();
'''


@app.route("/messages")
@login_required
def messages_page():
    me = int(session["user_id"]); conn = None
    try:
        conn = get_connection(); cur = conn.cursor()
        selected_id = request.args.get("user_id", type=int)
        selected = get_user_brief(cur, selected_id) if selected_id and selected_id != me else None
        query = request.args.get("q", "").strip()
        notes = []
        for person in followed_people(cur, me, 8):
            uid, username = person[0], person[1]
            notes.append(f'<a class="inbox-note" href="{url_for("messages_page", user_id=uid)}">{avatar_html(person[3], username)}<span>{escape(str(username or "User"))}</span></a>')
        list_html = inbox_list_html(cur, me, selected, query)
        if selected:
            sel_name = str(selected[2] or selected[1])
            chat_area = f'''<header class="chat-header"><a href="{url_for('messages_page')}" class="mobile-back" aria-label="Back to inbox">←</a>{avatar_html(selected[3], selected[1])}<div style="min-width:0"><strong>{escape(sel_name)}</strong><div class="muted">@{escape(str(selected[1]))}</div></div><span style="flex:1"></span><button type="button" class="secondary" aria-label="Voice call" title="Voice call" onclick="alert('Voice calls are not connected yet.')">☎</button><button type="button" class="secondary" aria-label="Video call" title="Video call" onclick="alert('Video calls are not connected yet.')">▣</button></header><div class="chat-scroll" id="chat-scroll"><div class="chat-empty" id="chat-empty"><div class="send-icon">✉</div><h2>{escape(sel_name)}</h2><p>This is the beginning of your conversation.</p></div></div><form class="chat-composer" id="chat-composer"><textarea id="chat-message" rows="1" maxlength="2000" placeholder="Message...  (Enter = send, Shift+Enter = new line)" aria-label="Message"></textarea><button type="submit" aria-label="Send message">Send</button></form>'''
        else:
            chat_area = '''<div class="chat-empty"><div class="send-icon">✉</div><h2>Your messages</h2><p>Select a conversation, or search for someone to start a chat.</p><button type="button" class="btn" onclick="document.getElementById('inbox-search-input').focus()">Send message</button></div>'''
        js = CHAT_JS.replace("__ME__", str(me)).replace("__OTHER__", str(int(selected[0])) if selected else "null")
        content = f'''<div class="inbox-layout {"chat-selected" if selected else ""}" id="inbox-layout"><aside class="inbox-left"><div class="inbox-head"><div class="inbox-account"><span>{escape(str(session.get('username') or 'Messages'))}</span><a href="{url_for('messages_page',compose=1)}" aria-label="New message" title="New message">✎</a></div><div class="inbox-tabs"><button type="button" class="active">Messages</button></div></div><form class="inbox-search" method="get" action="{url_for('messages_page')}"><input id="inbox-search-input" name="q" value="{escape(query)}" placeholder="Search people or conversations" aria-label="Search conversations"></form><div class="inbox-notes">{''.join(notes) or '<span class="muted">People you follow will appear here.</span>'}</div><div class="conversation-list">{list_html}</div></aside><section class="inbox-main">{chat_area}</section></div><script>{js}</script>'''
        return render_template_string(PAGE, title="Messages", content=content)
    except Exception:
        app.logger.exception("Messages page failed"); return "Messages could not be loaded. Please try again.", 500
    finally:
        if conn: conn.close()


SETTINGS_CATEGORIES = {
    "Account": [
        ("Edit Profile", "Update your name, bio, and profile photo.", "link", "/edit-profile"),
        ("Personal Details", "View and update your personal details.", "link", "/settings/personal-details"),
        ("Change Username", "Choose a new unique username for your account.", "link", "/settings/username"),
        ("Change Email", "Manage the email address used for your account.", "info", "Email changes need email verification before they can be applied."),
        ("Change Phone Number", "Manage your account phone number.", "info", "Phone number changes need verification before they can be applied."),
        ("Change Password", "Update your password using your current password.", "link", "/settings/password"),
        ("Account Ownership and Control", "Review account control options.", "info", "Account ownership controls require a dedicated verified workflow."),
        ("Deactivate Account", "Temporarily disable access to your account.", "info", "Deactivation is not enabled yet; no account status has been changed."),
        ("Delete Account", "Permanently remove your account and associated content.", "info", "Deletion is not enabled yet. No data has been deleted."),
    ],
    "Privacy": [
        ("Private Account", "Limit who can see your posts and follow you.", "toggle", "private_account"),
        ("Account Visibility", "Choose whether your profile is discoverable.", "select", "visibility"),
        ("Blocked Accounts", "Review accounts you have blocked.", "info", "Blocking management requires a dedicated block list and backend table."),
        ("Restricted Accounts", "Limit interactions from selected accounts.", "info", "Restriction management requires a dedicated backend list."),
        ("Hidden Words", "Choose whether to filter potentially offensive words.", "toggle", "hidden_words"),
        ("Comments Control", "Allow or limit comments on your posts.", "select", "comments_control"),
        ("Mentions and Tags", "Choose who can mention or tag you.", "select", "mentions_tags"),
        ("Story Privacy", "Choose who can view your stories.", "select", "story_privacy"),
        ("Activity Status", "Let others see when you are active.", "toggle", "activity_status"),
    ],
    "Security": [
        ("Change Password", "Change your password securely.", "link", "/settings/password"),
        ("Two-Factor Authentication", "Add a second verification step when logging in.", "info", "Two-factor authentication needs an authenticator or email/SMS integration; it is not enabled."),
        ("Login Activity", "Review recent account logins.", "info", "Login history is not currently recorded by the app."),
        ("Where You're Logged In", "Review active sessions.", "info", "Session management needs a persistent server-side session store."),
        ("Saved Login Information", "Control whether login details are saved on this device.", "toggle", "saved_login"),
        ("Security Notifications", "Receive notices about important security events.", "toggle", "security_notifications"),
    ],
    "Notifications": [(n, "Choose whether to receive this type of notification.", "toggle", k) for n,k in [("Push Notifications","push_notifications"),("Email Notifications","email_notifications"),("Likes and Reactions","notify_likes"),("Comments","notify_comments"),("Followers","notify_followers"),("Messages","notify_messages"),("Live Videos","notify_live"),("Reminders","notify_reminders")]],
    "Appearance": [
        ("Theme", "Choose your preferred website theme.", "select", "theme"),
        ("Language", "Choose the language used by the interface.", "select", "language"),
        ("Font Size", "Adjust the interface text size.", "select", "font_size"),
    ],
    "Content & Preferences": [
        ("Saved Posts", "View posts you have saved.", "link", "/saved"),
        ("Archive", "Review archived posts.", "info", "Post archiving is not currently implemented."),
        ("Your Activity", "Review your interactions and account activity.", "info", "An activity history page is not currently implemented."),
        ("Search History", "Choose whether search history is retained.", "toggle", "save_search_history"),
        ("Recently Deleted", "Review content marked for deletion.", "info", "Recently deleted content requires a recoverable deletion workflow."),
        ("Content Preferences", "Personalize the content shown in your feed.", "select", "content_preferences"),
        ("Sensitive Content Controls", "Choose how sensitive content is handled.", "select", "sensitive_content"),
    ],
    "Messages": [
        ("Message Requests", "Choose whether message requests are allowed.", "select", "message_requests"),
        ("Who Can Message You", "Control who can send you messages.", "select", "who_can_message"),
        ("Group Chat Permissions", "Choose who can add you to group chats.", "select", "group_permissions"),
        ("Read Receipts", "Control whether read receipts are shown.", "toggle", "read_receipts"),
        ("Message Controls", "Manage message interaction preferences.", "info", "Message delivery controls require a complete messaging backend."),
    ],
    "Help & Support": [
        ("Help Center", "Get help using InstaClone.", "info", "A public help center has not been published yet."),
        ("Report a Problem", "Send a report about an issue.", "info", "Problem reporting needs a secure support submission endpoint."),
        ("Privacy Policy", "Read how account data is handled.", "info", "A production privacy policy must be written and published before public launch."),
        ("Terms and Conditions", "Review the terms for using this service.", "info", "Terms must be reviewed and published before public launch."),
        ("About", "Learn about this InstaClone project.", "info", "InstaClone is a learning project inspired by social media apps."),
    ],
}

SETTINGS_DEFAULTS = {
    "private_account": False, "visibility": "Public", "hidden_words": False,
    "comments_control": "Everyone", "mentions_tags": "Everyone", "story_privacy": "Everyone",
    "activity_status": True, "saved_login": False, "security_notifications": True,
    "push_notifications": True, "email_notifications": False, "notify_likes": True,
    "notify_comments": True, "notify_followers": True, "notify_messages": True,
    "notify_live": False, "notify_reminders": True, "theme": "Dark", "language": "English",
    "font_size": "Medium", "save_search_history": True, "content_preferences": "Balanced",
    "sensitive_content": "Standard", "message_requests": "People you follow", "who_can_message": "People you follow",
    "group_permissions": "People you follow", "read_receipts": True,
}

SETTING_CHOICES = {
    "visibility": ["Public", "Private"], "comments_control": ["Everyone", "People you follow", "Off"],
    "mentions_tags": ["Everyone", "People you follow", "No one"], "story_privacy": ["Everyone", "Close friends", "People you follow"],
    "theme": ["Dark", "Light", "System default"], "language": ["English"], "font_size": ["Small", "Medium", "Large"],
    "content_preferences": ["Balanced", "More relevant", "Less sensitive"], "sensitive_content": ["Standard", "Less", "More"],
    "message_requests": ["Everyone", "People you follow", "No one"], "who_can_message": ["Everyone", "People you follow", "No one"],
    "group_permissions": ["Everyone", "People you follow", "No one"],
}


def load_user_settings(cursor, user_id):
    cursor.execute("IF OBJECT_ID('dbo.UserSettings', 'U') IS NULL BEGIN CREATE TABLE dbo.UserSettings (UserID INT NOT NULL PRIMARY KEY, SettingsJson NVARCHAR(MAX) NOT NULL CONSTRAINT DF_UserSettings_Json DEFAULT N'{}', UpdatedAt DATETIME2 NOT NULL CONSTRAINT DF_UserSettings_UpdatedAt DEFAULT SYSUTCDATETIME()) END")
    cursor.execute("SELECT SettingsJson FROM dbo.UserSettings WHERE UserID=?", (user_id,))
    row = cursor.fetchone()
    saved = {}
    if row and row[0]:
        try: saved = json.loads(row[0])
        except (TypeError, ValueError): saved = {}
    return {**SETTINGS_DEFAULTS, **saved}


@app.route("/settings")
@login_required
def settings_page():
    conn = None
    try:
        conn = get_connection(); cur = conn.cursor()
        values = load_user_settings(cur, session["user_id"]); conn.commit()
        cur.execute("SELECT Username, Email FROM Users WHERE UserID=?", (session["user_id"],))
        user = cur.fetchone()
        categories_json = json.dumps({k:[{"name":n,"description":d,"kind":kind,"value":v} for n,d,kind,v in rows] for k,rows in SETTINGS_CATEGORIES.items()})
        choices_json = json.dumps(SETTING_CHOICES)
        values_json = json.dumps(values)
        content = '''<div class="container"><div style="margin:0 auto 20px;max-width:1100px"><h1>Settings</h1><p class="muted">Manage your account, privacy, security, and preferences.</p></div><div class="settings-layout"><aside class="settings-menu"><h2>Settings</h2><input id="settings-search" class="settings-search" type="search" placeholder="Search settings" aria-label="Search settings"><div id="settings-category-list"></div><div style="margin-top:16px"><a class="btn secondary" href="'''+url_for("logout")+'''">Log out</a></div></aside><section class="settings-panel"><div id="settings-content"><h2>Account</h2><p class="muted">Loading your settings…</p></div><div class="settings-actions"><button id="settings-cancel" type="button" class="secondary">Reset changes</button><button id="settings-save" type="button">Save Changes</button></div></section></div></div>
<script>
const SETTINGS_CATEGORIES = '''+categories_json+''';
const SETTING_CHOICES = '''+choices_json+''';
const SAVED_VALUES = '''+values_json+''';
let currentCategory = 'Account'; let working = structuredClone(SAVED_VALUES);
const showSettingsToast=message=>{const el=document.getElementById('toast');if(el){el.textContent=message;el.hidden=false;setTimeout(()=>el.hidden=true,2600)}};
const categoryList=document.getElementById('settings-category-list'); const panel=document.getElementById('settings-content'); const search=document.getElementById('settings-search');
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function drawCategories(){categoryList.innerHTML='';Object.keys(SETTINGS_CATEGORIES).forEach(cat=>{const b=document.createElement('button');b.type='button';b.className='settings-category'+(cat===currentCategory?' active':'');b.textContent=cat;b.onclick=()=>{currentCategory=cat;drawCategories();drawPanel(search.value)};categoryList.appendChild(b)})}
function drawPanel(filter=''){const items=SETTINGS_CATEGORIES[currentCategory].filter(i=>(i.name+' '+i.description+' '+currentCategory).toLowerCase().includes(filter.toLowerCase()));panel.innerHTML='<h2>'+esc(currentCategory)+'</h2><p class="muted">Choose a setting to manage. Changes are saved to your account when you click Save Changes.</p>';
if(!items.length){panel.innerHTML+='<div class="settings-notice">No matching settings in this category.</div>';return}
items.forEach(item=>{const row=document.createElement('div');row.className='setting-row';row.dataset.name=item.name;const copy=document.createElement('div');copy.className='setting-copy';copy.innerHTML='<strong>'+esc(item.name)+'</strong><p>'+esc(item.description)+'</p>';const control=document.createElement('div');control.className='setting-control';
if(item.kind==='toggle'){const inp=document.createElement('input');inp.type='checkbox';inp.className='switch';inp.checked=Boolean(working[item.value]);inp.setAttribute('aria-label',item.name);inp.onchange=()=>working[item.value]=inp.checked;control.appendChild(inp)}
else if(item.kind==='select'){const sel=document.createElement('select');sel.setAttribute('aria-label',item.name);(SETTING_CHOICES[item.value]||[]).forEach(v=>{const op=document.createElement('option');op.value=v;op.textContent=v;sel.appendChild(op)});sel.value=working[item.value]||sel.options[0]?.value;sel.onchange=()=>{working[item.value]=sel.value;if(item.value==='theme'){const t=sel.value==='Light'?'light':'dark';document.documentElement.dataset.theme=t;try{localStorage.setItem('instaclone-theme',sel.value)}catch(e){}}};control.appendChild(sel)}
else if(item.kind==='link'){const a=document.createElement('a');a.className='btn secondary';a.href=item.value;a.textContent='Open';control.appendChild(a)}
else{const b=document.createElement('button');b.type='button';b.className='secondary';b.textContent='Details';b.onclick=()=>{panel.querySelectorAll('.settings-notice').forEach(n=>n.remove());const notice=document.createElement('div');notice.className='settings-notice';notice.style.marginTop='16px';notice.textContent=item.value;panel.appendChild(notice)};control.appendChild(b)}
row.append(copy,control);panel.appendChild(row)});}
search.addEventListener('input',()=>{const q=search.value.trim();if(q){let found=null;for(const [cat,items] of Object.entries(SETTINGS_CATEGORIES)){if(items.some(i=>(i.name+' '+i.description+' '+cat).toLowerCase().includes(q.toLowerCase()))){found=cat;break}}if(found&&found!==currentCategory){currentCategory=found;drawCategories()} }drawPanel(q)});
document.getElementById('settings-cancel').onclick=()=>{working=structuredClone(SAVED_VALUES);drawPanel(search.value);showSettingsToast('Unsaved changes discarded')};
document.getElementById('settings-save').onclick=async()=>{const b=document.getElementById('settings-save');b.disabled=true;try{const r=await fetch('/settings/save',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','Accept':'application/json','X-CSRFToken':window.CSRF},body:JSON.stringify(working)});const data=await r.json();if(!r.ok||!data.ok)throw new Error(data.message||'Could not save settings');Object.assign(SAVED_VALUES,working);if(working.theme){try{localStorage.setItem('instaclone-theme',working.theme)}catch(e){}document.documentElement.dataset.theme=working.theme==='Light'?'light':'dark'}showSettingsToast('Settings saved successfully')}catch(e){showSettingsToast(e.message)}finally{b.disabled=false}};
drawCategories();drawPanel();
</script>'''
        return render_template_string(PAGE, title="Settings", content=content)
    except Exception:
        if conn: conn.rollback()
        app.logger.exception("Settings page failed")
        return "Settings could not be loaded. Please check the application log.", 500
    finally:
        if conn: conn.close()


@app.route("/settings/save", methods=["POST"])
@login_required
def save_settings():
    data = request.get_json(silent=True)
    if not isinstance(data, dict): return jsonify(ok=False, message="Invalid settings payload."), 400
    allowed = set(SETTINGS_DEFAULTS)
    clean = {}
    for key, value in data.items():
        if key not in allowed: continue
        if isinstance(SETTINGS_DEFAULTS[key], bool):
            if not isinstance(value, bool): return jsonify(ok=False, message=f"Invalid value for {key}."), 400
            clean[key] = value
        elif isinstance(value, str) and value in SETTING_CHOICES.get(key, []): clean[key] = value
        else: return jsonify(ok=False, message=f"Invalid value for {key}."), 400
    conn=None
    try:
        conn=get_connection(); cur=conn.cursor(); existing=load_user_settings(cur, session["user_id"]); existing.update(clean)
        cur.execute("IF EXISTS (SELECT 1 FROM dbo.UserSettings WHERE UserID=?) UPDATE dbo.UserSettings SET SettingsJson=?, UpdatedAt=SYSUTCDATETIME() WHERE UserID=? ELSE INSERT INTO dbo.UserSettings (UserID, SettingsJson) VALUES (?,?)", (session["user_id"],json.dumps(existing),session["user_id"],session["user_id"],json.dumps(existing)))
        conn.commit(); return jsonify(ok=True)
    except Exception:
        if conn: conn.rollback()
        app.logger.exception("Saving settings failed"); return jsonify(ok=False,message="Settings could not be saved. Please try again."),500
    finally:
        if conn: conn.close()


@app.route("/settings/username", methods=["GET", "POST"])
@login_required
def change_username():
    conn = None
    try:
        conn = get_connection(); cur = conn.cursor()
        cur.execute("SELECT Username FROM Users WHERE UserID=?", (session["user_id"],))
        user = cur.fetchone()
        if not user: abort(404)
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            if not username or len(username) > 50 or any(ch.isspace() for ch in username):
                flash("Username must be 1–50 characters and cannot contain spaces.")
                return redirect(url_for("change_username"))
            cur.execute("SELECT COUNT(*) FROM Users WHERE Username=? AND UserID<>?", (username, session["user_id"]))
            if cur.fetchone()[0]:
                flash("That username is already in use.")
                return redirect(url_for("change_username"))
            cur.execute("UPDATE Users SET Username=? WHERE UserID=?", (username, session["user_id"]))
            conn.commit(); session["username"] = username
            flash("Username updated successfully.")
            return redirect(url_for("settings_page"))
        content = f'''<div class="container"><div class="card"><a class="btn secondary" href="{url_for('settings_page')}">Back to Settings</a><h1>Change Username</h1><p class="muted">Choose a unique username. Usernames cannot contain spaces.</p><form method="post"><label for="username">Username</label><input id="username" name="username" maxlength="50" value="{escape(str(user[0] or ''))}" required><button type="submit">Save Username</button></form></div></div>'''
        return render_template_string(PAGE, title="Change Username", content=content)
    except HTTPException:
        raise
    except Exception:
        if conn: conn.rollback()
        app.logger.exception("Change username failed")
        return "Username could not be changed. Please try again.", 500
    finally:
        if conn: conn.close()


@app.route("/settings/personal-details", methods=["GET", "POST"])
@login_required
def personal_details():
    conn = None
    try:
        conn = get_connection()
        cur = conn.cursor()
        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            if not full_name or len(full_name) > 100:
                flash("Full name is required and must be 100 characters or fewer.")
                return redirect(url_for("personal_details"))
            cur.execute("UPDATE Users SET FullName=? WHERE UserID=?", (full_name, session["user_id"]))
            conn.commit()
            flash("Personal details saved successfully.")
            return redirect(url_for("personal_details"))
        cur.execute("SELECT Username, Email, FullName FROM Users WHERE UserID=?", (session["user_id"],))
        user = cur.fetchone()
        if not user:
            abort(404)
        content = f"""<div class="container"><div class="card"><a class="btn secondary" href="{url_for('settings_page')}">Back to Settings</a><h1>Personal Information</h1><p class="muted">Review your account details. Email changes require a separate verification process.</p><form method="post"><label for="username">Username</label><input id="username" value="{escape(str(user[0] or ''))}" readonly><label for="email">Email address</label><input id="email" type="email" value="{escape(str(user[1] or ''))}" readonly><p class="muted">Email address cannot be changed here without email verification.</p><label for="full_name">Full name</label><input id="full_name" name="full_name" maxlength="100" value="{escape(str(user[2] or ''))}" required><button type="submit">Save Changes</button> <a class="btn secondary" href="{url_for('settings_page')}">Cancel</a></form></div></div>"""
        return render_template_string(PAGE, title="Personal Information", content=content)
    except HTTPException:
        raise
    except Exception:
        if conn:
            conn.rollback()
        app.logger.exception("Personal details page failed")
        return "Personal information could not be loaded. Please try again.", 500
    finally:
        if conn:
            conn.close()


@app.route("/settings/password", methods=["GET","POST"])
@login_required
def change_password():
    conn=None
    if request.method == "POST":
        current=request.form.get("current_password",""); new=request.form.get("new_password",""); confirm=request.form.get("confirm_password","")
        if len(new)<8 or new!=confirm: flash("New passwords must match and contain at least 8 characters."); return redirect(url_for("change_password"))
        try:
            conn=get_connection();cur=conn.cursor();cur.execute("SELECT PasswordHash FROM Users WHERE UserID=?",(session["user_id"],));row=cur.fetchone()
            if not row or not check_password_hash(row[0],current): flash("Current password is incorrect."); return redirect(url_for("change_password"))
            cur.execute("UPDATE Users SET PasswordHash=? WHERE UserID=?",(generate_password_hash(new),session["user_id"]));conn.commit();flash("Password changed successfully.");return redirect(url_for("settings_page"))
        except Exception:
            if conn: conn.rollback()
            app.logger.exception("Password change failed");flash("Password could not be changed. Please try again.");return redirect(url_for("change_password"))
        finally:
            if conn: conn.close()
    content='''<div class="container"><div class="card"><h1>Change Password</h1><p class="muted">Enter your current password, then choose a new password with at least 8 characters.</p><form method="post"><label for="current_password">Current password</label><input id="current_password" type="password" name="current_password" required autocomplete="current-password"><label for="new_password">New password</label><input id="new_password" type="password" name="new_password" minlength="8" required autocomplete="new-password"><label for="confirm_password">Confirm new password</label><input id="confirm_password" type="password" name="confirm_password" minlength="8" required autocomplete="new-password"><button type="submit">Save Password</button> <a class="btn secondary" href="/settings">Cancel</a></form></div></div>'''
    return render_template_string(PAGE,title="Change Password",content=content)


@app.route("/search",methods=["GET","POST"])
@login_required
def search_users():
    q=request.values.get("q","").strip(); users=[]; conn=None
    try:
        conn=get_connection(); cur=conn.cursor()
        if q:
            cur.execute("SELECT TOP 50 UserID,Username,FullName FROM Users WHERE Username LIKE ? OR FullName LIKE ? ORDER BY Username",("%"+q+"%","%"+q+"%")); users=cur.fetchall()
        def msg_btn(uid):
            if int(uid)==int(session["user_id"]): return ""
            return f'<a class="btn secondary" href="{url_for("messages_page",user_id=uid)}">Message</a>'
        rows=''.join(f'<div class="user-row"><div><strong>{escape(str(u[2] or u[1]))}</strong><br><a href="{url_for("user_profile",user_id=u[0])}">@{escape(str(u[1]))}</a></div><div class="actions"><a class="btn" href="{url_for("user_profile",user_id=u[0])}">View Profile</a>{msg_btn(u[0])}</div></div>' for u in users)
        content=f'''<div class="container"><div class="card"><h1>Search people</h1><form method="get"><input name="q" value="{escape(q)}" placeholder="Search username or name"><button>Search</button></form></div>{rows}</div>'''
        return render_template_string(PAGE,title="Search",content=content)
    except Exception:
        app.logger.exception("Search failed"); return "Search failed. Please try again.",500
    finally:
        if conn: conn.close()


@app.errorhandler(413)
def too_large(error):
    return "Upload limit exceeded. Keep videos under 50 MB and photos under 5 MB.",413


if __name__ == "__main__":
    ensure_schema()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)