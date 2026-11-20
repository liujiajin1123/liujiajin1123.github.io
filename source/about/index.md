---
title: 关于我
date: 2026-04-27 08:51:00
layout: page
---

<style>
.resume-page {
  --resume-primary: #2563eb;
  --resume-secondary: #0f766e;
  --resume-ink: #172033;
  --resume-muted: #64748b;
  --resume-line: #e5eaf2;
  --resume-soft: #f7f9fc;
  color: var(--resume-ink);
}

.resume-page * {
  box-sizing: border-box;
}

body:has(.resume-page) .waifu {
  display: none !important;
}

.resume-hero {
  position: relative;
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  gap: 1.5rem;
  align-items: center;
  overflow: hidden;
  margin-bottom: 1.25rem;
  padding: 2rem;
  border: 1px solid #dbe7fb;
  border-radius: 18px;
  background: linear-gradient(135deg, #f5f9ff 0%, #edf8f6 100%);
}

.resume-hero::after {
  content: "";
  position: absolute;
  right: -55px;
  bottom: -75px;
  width: 210px;
  height: 210px;
  border-radius: 50%;
  background: linear-gradient(135deg, rgba(37, 99, 235, .14), rgba(15, 118, 110, .08));
}

.resume-avatar {
  position: relative;
  z-index: 1;
  display: grid;
  width: 88px;
  height: 88px;
  place-items: center;
  border: 4px solid rgba(255, 255, 255, .8);
  border-radius: 24px;
  background: linear-gradient(135deg, var(--resume-primary), var(--resume-secondary));
  box-shadow: 0 12px 28px rgba(37, 99, 235, .2);
  color: #fff;
  font-size: 2rem;
  font-weight: 700;
}

.resume-intro {
  position: relative;
  z-index: 1;
}

.resume-eyebrow {
  margin: 0 0 .35rem !important;
  color: var(--resume-primary);
  font-size: .75rem;
  font-weight: 700;
  letter-spacing: .14em;
  text-transform: uppercase;
}

.resume-page .resume-name {
  margin: 0 0 .3rem !important;
  color: var(--resume-ink);
  font-size: 2rem;
  line-height: 1.2;
}

.resume-role {
  margin: 0 0 .8rem !important;
  color: #334155;
  font-size: 1rem;
  font-weight: 600;
}

.resume-summary {
  max-width: 840px;
  margin: 0 !important;
  color: #475569;
  line-height: 1.8;
}

.resume-tags {
  display: flex;
  flex-wrap: wrap;
  gap: .5rem;
  margin-top: 1rem;
}

.resume-tag {
  padding: .35rem .7rem;
  border: 1px solid rgba(37, 99, 235, .14);
  border-radius: 999px;
  background: rgba(255, 255, 255, .72);
  color: #31547d;
  font-size: .8rem;
}

.resume-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.15fr) minmax(280px, .85fr);
  gap: 1.25rem;
  align-items: start;
}

.resume-column {
  display: grid;
  gap: 1.25rem;
}

.resume-card {
  padding: 1.4rem 1.5rem;
  border: 1px solid var(--resume-line);
  border-radius: 16px;
  background: #fff;
  box-shadow: 0 8px 24px rgba(15, 23, 42, .045);
}

.resume-section-title {
  display: flex;
  gap: .65rem;
  align-items: center;
  margin: 0 0 1.1rem !important;
  color: var(--resume-ink) !important;
  font-size: 1.08rem !important;
  line-height: 1.3;
}

.resume-section-title i {
  display: grid;
  width: 32px;
  height: 32px;
  place-items: center;
  border-radius: 10px;
  background: #edf4ff;
  color: var(--resume-primary);
  font-size: .9rem;
}

.resume-timeline {
  position: relative;
  display: grid;
  gap: 1.25rem;
  padding-left: 1.15rem;
}

.resume-timeline::before {
  content: "";
  position: absolute;
  top: .45rem;
  bottom: .45rem;
  left: 3px;
  width: 2px;
  background: #dce7f6;
}

.resume-entry {
  position: relative;
}

.resume-entry::before {
  content: "";
  position: absolute;
  top: .42rem;
  left: -1.25rem;
  width: 10px;
  height: 10px;
  border: 2px solid #fff;
  border-radius: 50%;
  background: var(--resume-primary);
  box-shadow: 0 0 0 2px #bcd1f4;
}

.resume-entry-head {
  display: flex;
  gap: .75rem;
  align-items: baseline;
  justify-content: space-between;
}

.resume-entry-title {
  margin: 0 !important;
  color: #1e293b;
  font-size: .96rem;
  font-weight: 700;
}

.resume-date {
  flex: 0 0 auto;
  color: var(--resume-muted);
  font-size: .78rem;
  font-variant-numeric: tabular-nums;
}

.resume-entry-subtitle {
  margin: .28rem 0 0 !important;
  color: #475569;
  font-size: .88rem;
}

.resume-entry-note {
  margin: .32rem 0 0 !important;
  color: var(--resume-muted);
  font-size: .82rem;
  line-height: 1.6;
}

.resume-skills {
  display: flex;
  flex-wrap: wrap;
  gap: .6rem;
}

.resume-skill {
  padding: .55rem .72rem;
  border-radius: 10px;
  background: var(--resume-soft);
  color: #334155;
  font-size: .84rem;
}

.resume-awards {
  display: grid;
  gap: .75rem;
}

.resume-award {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  gap: .75rem;
  align-items: start;
  padding: .8rem;
  border-radius: 12px;
  background: linear-gradient(135deg, #fff9e8, #fffdf6);
}

.resume-award-icon {
  display: grid;
  width: 34px;
  height: 34px;
  place-items: center;
  border-radius: 10px;
  background: #f59e0b;
  color: #fff;
}

.resume-award p {
  margin: 0 !important;
  color: #3f3a2d;
  font-size: .86rem;
  line-height: 1.55;
}

.resume-award strong {
  color: #7c4a03;
}

.resume-contact {
  display: flex;
  gap: .75rem;
  align-items: center;
  padding: .9rem 1rem;
  border-radius: 12px;
  background: #f1f6ff;
}

.resume-contact i {
  color: var(--resume-primary);
}

.resume-contact a {
  overflow-wrap: anywhere;
  font-size: .88rem;
  font-weight: 600;
}

.night .resume-page {
  --resume-ink: #e5e7eb;
  --resume-muted: #94a3b8;
  --resume-line: #303745;
  --resume-soft: #252b36;
}

.night .resume-hero {
  border-color: #334155;
  background: linear-gradient(135deg, #202938, #192f32);
}

.night .resume-role,
.night .resume-summary,
.night .resume-entry-title,
.night .resume-entry-subtitle,
.night .resume-skill {
  color: #cbd5e1;
}

.night .resume-tag,
.night .resume-card {
  border-color: #303745;
  background: #1b1f27;
}

.night .resume-section-title i,
.night .resume-contact {
  background: #222f43;
}

.night .resume-award {
  background: #29261f;
}

.night .resume-award p {
  color: #e5dcc6;
}

.night .resume-award strong {
  color: #fbbf24;
}

@media (max-width: 760px) {
  .resume-hero {
    grid-template-columns: 1fr;
    padding: 1.4rem;
  }

  .resume-avatar {
    width: 70px;
    height: 70px;
    border-radius: 20px;
    font-size: 1.6rem;
  }

  .resume-page .resume-name {
    font-size: 1.65rem;
  }

  .resume-grid {
    grid-template-columns: 1fr;
  }

  .resume-entry-head {
    display: block;
  }

  .resume-date {
    display: block;
    margin-top: .2rem;
  }
}
</style>

<div class="resume-page">
<section class="resume-hero">
<div class="resume-avatar" aria-hidden="true">刘</div>
<div class="resume-intro">
<p class="resume-eyebrow">About Me</p>
<h2 class="resume-name">刘佳进</h2>
<p class="resume-role">网络空间安全硕士在读 · Java 软件开发</p>
<p class="resume-summary">目前就读于南昌大学软件学院，研究方向为人脸识别中的对抗攻击。在攻读硕士研究生之前，曾从事 Java 软件开发工作，具有约两年的企业开发经验。希望将软件工程经验与网络安全背景结合起来。</p>
<div class="resume-tags" aria-label="个人方向">
<span class="resume-tag">Java 后端</span>
<span class="resume-tag">网络空间安全</span>
<span class="resume-tag">安全平台开发</span>
<span class="resume-tag">对抗攻击</span>
</div>
</div>
</section>

<div class="resume-grid">
<div class="resume-column">
<section class="resume-card">
<h2 class="resume-section-title"><i class="fas fa-graduation-cap" aria-hidden="true"></i>教育经历</h2>
<div class="resume-timeline">
<div class="resume-entry">
<div class="resume-entry-head">
<p class="resume-entry-title">南昌大学软件学院</p>
<span class="resume-date">2025.09—2028.06</span>
</div>
<p class="resume-entry-subtitle">网络空间安全 · 全日制硕士研究生（在读）</p>
<p class="resume-entry-note">研究方向：人脸识别中的对抗攻击</p>
</div>
<div class="resume-entry">
<div class="resume-entry-head">
<p class="resume-entry-title">南昌大学生命科学学院</p>
<span class="resume-date">2017.09—2021.06</span>
</div>
<p class="resume-entry-subtitle">水产养殖 · 农学学士</p>
</div>
</div>
</section>

<section class="resume-card">
<h2 class="resume-section-title"><i class="fas fa-briefcase" aria-hidden="true"></i>工作经历</h2>
<div class="resume-timeline">
<div class="resume-entry">
<div class="resume-entry-head">
<p class="resume-entry-title">北京外企德科人力资源有限公司（华为 OD）</p>
<span class="resume-date">2022.08—2024.08</span>
</div>
<p class="resume-entry-subtitle">软件开发工程师 · 派驻华为项目</p>
</div>
</div>
</section>
</div>

<div class="resume-column">
<section class="resume-card">
<h2 class="resume-section-title"><i class="fas fa-code" aria-hidden="true"></i>技术方向</h2>
<div class="resume-skills">
<span class="resume-skill">Java 后端与应用系统开发</span>
<span class="resume-skill">网络空间安全</span>
<span class="resume-skill">人脸识别中的对抗攻击</span>
<span class="resume-skill">安全平台与安全工具工程化</span>
</div>
</section>

<section class="resume-card">
<h2 class="resume-section-title"><i class="fas fa-trophy" aria-hidden="true"></i>荣誉奖项</h2>
<div class="resume-awards">
<div class="resume-award">
<span class="resume-award-icon"><i class="fas fa-medal" aria-hidden="true"></i></span>
<p><strong>全国三等奖</strong><br>第二十三届中国研究生数学建模竞赛（队长）</p>
</div>
<div class="resume-award">
<span class="resume-award-icon"><i class="fas fa-award" aria-hidden="true"></i></span>
<p><strong>省级二等奖</strong><br>2026年江西省研究生数学建模竞赛</p>
</div>
</div>
</section>

<section class="resume-card">
<h2 class="resume-section-title"><i class="fas fa-paper-plane" aria-hidden="true"></i>联系方式</h2>
<div class="resume-contact">
<i class="fas fa-envelope" aria-hidden="true"></i>
<a href="mailto:jiajinliu1123@outlook.com">jiajinliu1123@outlook.com</a>
</div>
</section>
</div>
</div>
</div>
