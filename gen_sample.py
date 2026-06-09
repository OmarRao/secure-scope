"""Generate the sample report HTML for the README screenshots."""
import sys, os, shutil
from datetime import datetime
sys.path.insert(0, '.')

os.environ['GITHUB_TOKEN'] = os.environ.get('GITHUB_TOKEN', '')

from analyzer import analyze
from ui.github_info import fetch_repo_info
from flask import Flask, render_template

app = Flask(__name__, template_folder='ui/templates')

REPO_URL = 'https://github.com/OmarRao/analyzer'

print('[1/3] Fetching GitHub repository info...')
gh_info = fetch_repo_info(REPO_URL)
print(f"      {gh_info.get('full_name')} | Stars: {gh_info.get('stars')} | Lang: {gh_info.get('language')}")

print('[2/3] Running Semgrep analysis...')
result = analyze(REPO_URL)
findings = [f.__dict__ for f in result.findings]
print(f"      {len(findings)} findings | {len(result.dependency_vulns)} CVEs")

ts = datetime.now().strftime('%Y%m%d_%H%M%S')

score_raw = (
    len([f for f in findings if f.get('severity') == 'ERROR']) * 10 +
    len([f for f in findings if f.get('severity') == 'WARNING']) * 3 +
    len(result.dependency_vulns) * 8
)
score = min(score_raw, 100)
if score >= 70:   grade, gcolor = 'CRITICAL', '#f25757'
elif score >= 45: grade, gcolor = 'HIGH',     '#e6a817'
elif score >= 20: grade, gcolor = 'MEDIUM',   '#4f8ef7'
else:             grade, gcolor = 'LOW',      '#3ecf79'

print(f'[3/3] Building HTML report (score={score}, grade={grade})...')
with app.app_context():
    html = render_template(
        'report.html',
        generated_at=datetime.now().strftime('%Y-%m-%d %H:%M UTC'),
        repo_url=REPO_URL,
        repo_slug='analyzer',
        ts=ts,
        gh_info=gh_info,
        summary=result.summary(),
        findings=findings,
        dependency_vulns=result.dependency_vulns,
        runtime=None,
        score=score,
        grade=grade,
        gcolor=gcolor,
    )

out_path = 'reports/sample_report_ui.html'
with open(out_path, 'w', encoding='utf-8') as f:
    f.write(html)

print(f'      Saved: {out_path}')
shutil.rmtree(result.repo_path, ignore_errors=True)
print('Done.')
