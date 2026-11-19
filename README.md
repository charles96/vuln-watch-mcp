# vuln-watch-mcp

Claude Code나 Codex가 코딩 중에 **보안 취약점을 찾고, 수정 방법까지 받아서 직접 고칠 수 있게** 해 주는 MCP 서버입니다.

| 데이터 소스 | 용도 |
|---|---|
| [CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | 실제로 악용되고 있는 취약점 (조치 기한, 랜섬웨어 악용 여부, 필수 조치) |
| [NVD CVE API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0) | CVE 상세, CVSS, CWE, 영향받는 버전 범위, 패치 링크 |

---

## 빠른 시작

> 요구 사항: **Node.js 18 이상**, Git.
> 저장소가 **비공개**라서 설치하는 PC에 이 저장소 접근 권한이 있는 GitHub 인증이 필요합니다. 아래 명령으로 확인하세요.
> ```bash
> gh auth status          # charles96 계정이 활성 상태인지 확인
> gh auth setup-git       # git/npm이 gh 인증을 쓰도록 설정
> ```

### 방법 A: 클론해서 설치 (권장, 업데이트는 `git pull`)

```bash
git clone https://github.com/charles96/vuln-watch-mcp.git
cd vuln-watch-mcp
npm install
npm run smoke           # 도구 목록이 나오면 설치 완료
```

이후 등록할 때 쓰는 실행 경로는 `node <클론한 경로>/src/index.js`입니다.

### 방법 B: 클론 없이 npx로 바로 실행

```bash
npx -y github:charles96/vuln-watch-mcp
```

> npx는 받은 버전을 캐시합니다. 최신 커밋을 받으려면 `npx -y github:charles96/vuln-watch-mcp#main`처럼 브랜치나 커밋을 지정하거나 `npm cache clean --force`를 실행하세요.

---

## Claude Code에 등록

```bash
# 방법 A (클론)
claude mcp add vuln-watch --scope user \
  -e NVD_API_KEY=발급받은키 \
  -- node /절대경로/vuln-watch-mcp/src/index.js

# 방법 B (npx)
claude mcp add vuln-watch --scope user \
  -e NVD_API_KEY=발급받은키 \
  -- npx -y github:charles96/vuln-watch-mcp
```

- `--scope user`: 모든 프로젝트에서 사용합니다. 현재 프로젝트에서만 쓰려면 `--scope project`를 지정하세요(`.mcp.json`이 생성되어 팀과 공유됩니다).
- 확인: `claude mcp list` 또는 Claude Code 안에서 `/mcp`를 실행합니다.
- Windows 네이티브(WSL이 아닌 환경)에서 npx를 쓰는 경우: `-- cmd /c npx -y github:charles96/vuln-watch-mcp`

## Codex에 등록

`~/.codex/config.toml`에 추가합니다.

```toml
[mcp_servers.vuln-watch]
command = "node"
args = ["/절대경로/vuln-watch-mcp/src/index.js"]
# npx 방식: command = "npx", args = ["-y", "github:charles96/vuln-watch-mcp"]
env = { NVD_API_KEY = "발급받은키" }
startup_timeout_sec = 30
tool_timeout_sec = 600   # 의존성 스캔은 오래 걸릴 수 있습니다 (기본값 60초)
```

확인: `codex mcp list`

## NVD API 키 (무료, 강력 권장)

[여기서 신청](https://nvd.nist.gov/developers/request-an-api-key)하면 메일로 키를 받습니다.

| | 요청 한도 | 스캔 1회 기본 패키지 수 |
|---|---|---|
| 키 없음 | 30초당 5회 (요청당 약 6.5초 대기) | 10개 |
| 키 있음 | 30초당 50회 (요청당 약 0.7초 대기) | 60개 |

---

## 사용 예시

에이전트에게 자연어로 요청하면 알맞은 도구를 골라 호출합니다.

- "이 프로젝트 의존성 보안 취약점 점검하고 고쳐줘"
- "최근 2주간 나온 Python 심각 취약점 알려줘"
- "next 15.5.0에 취약점 있어?"
- "CVE-2021-44228, 우리 log4j 2.14.1에서 어떻게 고쳐?"
- Claude Code에서 `/mcp__vuln-watch__security_audit`: 스캔 → 최신 취약점 확인 → 수정 → 재검증을 한 번에 진행합니다.

## 도구

| 도구 | 설명 |
|---|---|
| `scan_project_dependencies` | `package-lock.json`/`package.json`, `requirements*.txt`, `go.mod`를 읽어 모든 의존성 버전을 점검합니다. 직접 의존성을 먼저 보고, 남은 패키지는 `offset`으로 이어서 스캔합니다. |
| `check_package` | 패키지나 제품 하나의 버전을 점검합니다 (`lodash 4.17.15`, `django 3.2.0`, `nginx 1.18.0` 등). |
| `latest_ecosystem_vulnerabilities` | 언어/생태계별 최신 CVE를 최신순으로 보여 줍니다 (npm, python, go, java, php, ruby, rust, dotnet). |
| `search_vulnerabilities` | NVD 키워드 검색입니다. 최신순이며 `ecosystem`, `cwe`, `days`, `kev_only`로 거를 수 있습니다. |
| `get_vulnerability` | CVE 하나의 전체 정보를 보여 줍니다. `installed_version`을 주면 그 버전 기준 수정 버전을 계산합니다. |
| `check_kev` | 여러 CVE ID가 KEV에 있는지 한 번에 확인합니다 (로컬 조회라 빠름). |
| `search_kev` | KEV를 벤더, 제품, 키워드, 최근 추가 기간, 랜섬웨어 악용 여부로 검색합니다. |

모든 도구는 `format: "json"`으로 구조화된 결과를 받을 수 있습니다.

## 결과에 포함되는 정보

| 항목 | 내용 |
|---|---|
| 우선순위 | 🔥 KEV(실제 악용) → CRITICAL/HIGH → 최신순 |
| 수정 버전 | NVD 버전 범위 상한을 쓰고, CVE 설명의 "fixed in X"와 비교해 더 안전한(높은) 버전을 권장 |
| 업그레이드 명령 | `npm install x@y`, `pip install "x>=y"`, `go get x@vY` 등 생태계별 명령 |
| 간접 의존성 | `npm ls`, `overrides`/`resolutions`, constraints로 고정하는 방법 |
| 메이저 업그레이드 경고 | 호환성이 깨지는 변경이 있을 수 있으면 경고 |
| 코드 수정 가이드 | CWE별 코드 수준 수정 방법 (예: CWE-1321 프로토타입 오염 → `__proto__` 키 차단) |
| KEV 정보 | 등재일, CISA 조치 기한, 랜섬웨어 악용 여부, 필수 조치 |
| 참고 링크 | 패치 커밋, 벤더 권고문, GHSA를 우선 표시 |
| 조치 계획 | 패키지별로 모든 CVE를 해결하는 최종 목표 버전 |

---

## 저장소 구조

```
vuln-watch-mcp/
├── src/
│   ├── index.js         # MCP 서버 진입점: 도구 7개, security_audit 프롬프트, 서버 안내문
│   ├── kev.js           # CISA KEV 카탈로그 다운로드, 캐시, 검색
│   ├── nvd.js           # NVD API 클라이언트 (속도 제한, 재시도, 캐시), CVSS/CPE 파싱, 버전 비교
│   ├── report.js        # 결과 생성: 수정 버전 계산, 업그레이드 명령, 정렬, Markdown 출력
│   ├── deps.js          # 의존성 파일 파서 (npm lockfile v1~v3, package.json, requirements.txt, go.mod)
│   ├── ecosystems.js    # 언어별 설정 (CPE 플랫폼, 검색 키워드, 업그레이드 명령 템플릿)
│   ├── remediation.js   # CWE별 코드 수정 가이드
│   └── cache.js         # 메모리 + 디스크 캐시 (오프라인이면 만료된 캐시 사용)
├── scripts/
│   └── smoke.js         # stdio로 서버를 띄워 도구를 호출하는 테스트 클라이언트
├── examples/
│   ├── vulnerable-node/    # 취약한 버전이 고정된 Node 샘플 (lodash, minimist, jsonwebtoken)
│   └── vulnerable-python/  # 취약한 버전이 고정된 Python 샘플 (django, requests)
├── package.json
└── README.md
```

## 테스트

```bash
npm run smoke                                         # 도구와 프롬프트 목록
node scripts/smoke.js check_kev '{"cve_ids":["CVE-2021-44228"]}'
node scripts/smoke.js scan_project_dependencies '{"path":"examples/vulnerable-node"}'
node scripts/smoke.js latest_ecosystem_vulnerabilities '{"ecosystem":"npm","days":14}'
```

## 환경 변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `NVD_API_KEY` | (없음) | NVD API 키 |
| `KEV_TTL_HOURS` | 6 | KEV 카탈로그 캐시 유지 시간 |
| `NVD_TTL_HOURS` | 12 | NVD 응답 캐시 유지 시간 |
| `VULN_WATCH_CACHE_DIR` | `~/.cache/vuln-watch-mcp` | 디스크 캐시 위치 |

## 문제 해결

| 증상 | 조치 |
|---|---|
| npx 설치 중 `Permission denied` / `Repository not found` | 비공개 저장소라서 생기는 문제입니다. `gh auth status`로 접근 권한이 있는 계정이 활성인지 확인하고 `gh auth setup-git`을 실행하세요. |
| Codex에서 스캔이 타임아웃됨 | `tool_timeout_sec`를 늘리거나 `max_packages`를 줄이세요. `NVD_API_KEY`를 설정하면 훨씬 빨라집니다. |
| `NVD HTTP 403/429` | 요청 한도 초과입니다. 자동으로 재시도하지만, 계속되면 API 키를 설정하세요. |
| 도구가 보이지 않음 | 등록 후 Claude Code나 Codex를 재시작하고 `/mcp`(Claude Code) 또는 `codex mcp list`로 상태를 확인하세요. |

## 한계

- 버전 매칭은 NVD의 CPE 데이터에 의존합니다. CPE가 없는 패키지나 NVD가 아직 분석하지 않은 신규 CVE(`Awaiting Analysis`)는 버전 스캔에 잡히지 않습니다. `latest_ecosystem_vulnerabilities`와 `search_vulnerabilities`의 키워드 검색으로 보완하세요.
- 패키지 이름은 CPE product 이름으로 바꿔 매칭합니다 (예: `@scope/name` → `name`). `Match confidence: medium`으로 표시된 결과는 같은 프로젝트인지 직접 확인해야 합니다.
- lockfile 없이 `package.json`만 있으면 `^1.2.3` 같은 범위를 최소 버전(`1.2.3`)으로 간주합니다. 정확한 결과를 위해 lockfile을 함께 두세요.
