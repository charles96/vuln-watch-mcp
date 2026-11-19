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

| 분류 | 도구 | 한 줄 설명 |
|---|---|---|
| 내 프로젝트 점검 | [`scan_project_dependencies`](#scan_project_dependencies) | 프로젝트 의존성 전체 스캔 + 조치 계획 |
| | [`check_package`](#check_package) | 패키지/제품 하나의 특정 버전 점검 |
| 최신 취약점 파악 | [`latest_ecosystem_vulnerabilities`](#latest_ecosystem_vulnerabilities) | 언어/생태계별 최신 CVE |
| | [`search_vulnerabilities`](#search_vulnerabilities) | NVD 키워드 검색 |
| 특정 CVE 조사 | [`get_vulnerability`](#get_vulnerability) | CVE 하나의 전체 정보와 수정 버전 |
| 실제 악용 여부 | [`check_kev`](#check_kev) | CVE 목록의 KEV 등재 여부 확인 |
| | [`search_kev`](#search_kev) | KEV 카탈로그 검색 |

공통 사항:
- **결과 정렬:** 🔥 KEV(실제 악용) → CRITICAL/HIGH → 최신순
- **심각도 값:** `min_severity`에는 `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`을 넣습니다.
- **생태계 값:** `ecosystem`에는 `npm`(`javascript`, `typescript`, `node`), `pypi`(`python`), `go`, `maven`(`java`), `composer`(`php`), `rubygems`(`ruby`), `cargo`(`rust`), `nuget`(`dotnet`)을 쓸 수 있습니다. 괄호 안은 같은 뜻으로 받는 별칭입니다.
- **결과 형식:** `check_kev`를 뺀 모든 도구는 `format: "json"`으로 구조화된 결과를 받을 수 있습니다 (기본값 `markdown`).

### `scan_project_dependencies`

프로젝트 폴더의 의존성 파일을 읽어, 설치된 버전마다 알려진 취약점이 있는지 NVD와 KEV로 확인합니다. 결과 맨 위에 패키지별 **조치 계획**(목표 버전, 실행할 명령, 메이저 업그레이드 경고)이 나오고, 그 아래 CVE별 상세가 이어집니다.

- **읽는 파일:** `package-lock.json`(v1~v3, 없으면 `package.json`), `requirements*.txt`, `go.mod`
- **스캔 순서:** 직접 의존성을 먼저 보고 간접 의존성을 봅니다. 한 번에 다 못 보면 `offset=N으로 이어서 호출하라`는 안내가 나옵니다.

| 파라미터 | 필수 | 기본값 | 설명 |
|---|---|---|---|
| `path` | ✅ | | 프로젝트 루트 폴더 또는 의존성 파일 경로 |
| `include_dev` | | `false` | devDependencies 포함 |
| `include_transitive` | | `true` | lockfile의 간접 의존성 포함 |
| `max_packages` | | 키 없음 10 / 키 있음 60 | 이번 호출에서 점검할 패키지 수 (1~500) |
| `offset` | | `0` | 앞의 N개를 건너뜀 (이전 스캔 이어서 하기) |
| `min_severity` | | | 이 심각도 이상만 표시 |

```json
{ "path": "/home/me/my-app", "include_dev": true, "min_severity": "HIGH" }
```

### `check_package`

라이브러리나 제품 하나의 특정 버전에 영향을 주는 CVE를 모두 찾습니다. 새 패키지를 추가하거나 버전을 올리기 전에 쓰면 좋습니다. 결과 형식은 `scan_project_dependencies`와 같습니다(조치 계획 + CVE 상세).

| 파라미터 | 필수 | 기본값 | 설명 |
|---|---|---|---|
| `name` | ✅ | | 패키지/제품 이름. 예: `lodash`, `@babel/traverse`, `django`, `github.com/gin-gonic/gin`, `nginx` |
| `version` | ✅ | | 설치된 버전. 예: `4.17.15` |
| `ecosystem` | | | 생태계. 지정하면 다른 플랫폼 CVE를 걸러내고 업그레이드 명령을 만들어 줍니다. |
| `vendor` | | | CPE 벤더 이름으로 결과를 좁힘. 예: `djangoproject`, `f5`, `openssl` |
| `min_severity` | | | 이 심각도 이상만 표시 |

```json
{ "name": "lodash", "version": "4.17.15", "ecosystem": "npm" }
```

### `latest_ecosystem_vulnerabilities`

특정 언어/생태계에서 최근 공개된 CVE를 최신순으로 보여 줍니다. NVD의 플랫폼 정보(CPE)로 찾은 결과에 키워드 검색 결과를 합쳐서, NVD가 아직 분석하지 않은 신규 CVE도 포함합니다.

| 파라미터 | 필수 | 기본값 | 설명 |
|---|---|---|---|
| `ecosystem` | ✅ | | 생태계 |
| `days` | | `30` | 최근 N일 (1~120, NVD 제한) |
| `keyword` | | | 추가로 좁힐 키워드. 예: `express`, `deserialization` |
| `min_severity` | | | 이 심각도 이상만 표시 |
| `kev_only` | | `false` | KEV에 등재된 것만 |
| `limit` | | `20` | 최대 결과 수 (1~100) |

```json
{ "ecosystem": "python", "days": 14, "min_severity": "HIGH" }
```

### `search_vulnerabilities`

NVD CVE 설명문을 키워드로 검색합니다 (최신순, 여러 단어는 모두 포함된 것만). 라이브러리, 프레임워크, 취약점 유형으로 찾을 때 씁니다.

| 파라미터 | 필수 | 기본값 | 설명 |
|---|---|---|---|
| `keyword` | ✅ | | 검색어. 예: `next.js middleware`, `prototype pollution`, `log4j` |
| `ecosystem` | | | 다른 플랫폼 대상 CVE 제외 |
| `days` | | | 최근 N일 안에 공개된 것만 (1~120) |
| `cwe` | | | CWE로 거르기. 예: `CWE-79` |
| `min_severity` | | | 이 심각도 이상만 표시 |
| `kev_only` | | `false` | KEV에 등재된 것만 |
| `exact_match` | | `false` | 검색어를 정확한 구문으로 취급 |
| `limit` | | `15` | 최대 결과 수 (1~100) |

```json
{ "keyword": "next.js", "ecosystem": "npm", "days": 60 }
```

### `get_vulnerability`

CVE 하나의 전체 정보를 보여 줍니다. 로그, `npm audit` 결과, 보안 공지에 CVE 번호가 나왔을 때 씁니다. `installed_version`을 주면 **그 버전 기준으로 어느 버전으로 올려야 하는지** 계산합니다.

- **결과:** 설명, CVSS 점수와 벡터, CWE와 코드 수정 가이드, 영향받는 버전 범위(요청한 제품 우선, 최대 25개), KEV 정보, 패치/권고 링크(최대 30개)

| 파라미터 | 필수 | 기본값 | 설명 |
|---|---|---|---|
| `cve_id` | ✅ | | CVE ID. 예: `CVE-2021-44228` |
| `installed_version` | | | 사용 중인 버전 (수정 버전 계산용) |
| `product` | | | CVE에 여러 제품이 걸려 있을 때 내가 쓰는 제품의 CPE 이름. 예: `log4j` |
| `ecosystem` | | | 업그레이드 명령 생성용 생태계 |

```json
{ "cve_id": "CVE-2021-44228", "installed_version": "2.14.1", "product": "log4j" }
```

### `check_kev`

CVE 목록이 CISA KEV(실제로 악용되고 있는 취약점 목록)에 있는지 한 번에 확인합니다. 내려받아 둔 카탈로그에서 조회하므로 빠릅니다. 등재된 CVE는 조치 기한, 랜섬웨어 악용 여부, CISA 필수 조치를 함께 보여 줍니다.

| 파라미터 | 필수 | 기본값 | 설명 |
|---|---|---|---|
| `cve_ids` | ✅ | | CVE ID 배열 (1~500개) |

```json
{ "cve_ids": ["CVE-2021-44228", "CVE-2020-8203"] }
```

### `search_kev`

KEV 카탈로그를 직접 검색합니다 (최근 추가순). "최근 한 달간 새로 악용되기 시작한 취약점" 같은 질문에 씁니다.

| 파라미터 | 필수 | 기본값 | 설명 |
|---|---|---|---|
| `query` | | | 검색어 (CVE ID, 벤더, 제품, 이름, 설명에서 모든 단어 포함) |
| `vendor` | | | 벤더 이름 일부. 예: `microsoft` |
| `product` | | | 제품 이름 일부. 예: `exchange` |
| `days` | | | 최근 N일 안에 KEV에 추가된 것만 |
| `ransomware_only` | | `false` | 랜섬웨어 악용이 확인된 것만 |
| `limit` | | `25` | 최대 결과 수 (1~200) |

```json
{ "days": 30, "ransomware_only": true }
```

### 프롬프트: `security_audit`

도구를 하나씩 부르는 대신 **점검부터 수정까지 한 번에** 진행하도록 에이전트에게 주는 작업 지시입니다. `path`(선택, 기본값은 현재 폴더)를 받습니다.

1. `scan_project_dependencies`로 의존성 전체 스캔 (남은 패키지가 없을 때까지 `offset`으로 반복)
2. 감지된 생태계마다 `latest_ecosystem_vulnerabilities`로 최근 30일 취약점 확인
3. KEV → CRITICAL → HIGH 순으로 수정: 의존성 파일과 lockfile 업데이트(간접 의존성은 overrides/resolutions), 코드에서 취약한 기능을 쓰는 곳을 찾아 CWE 가이드대로 수정
4. 다시 스캔해서 확인하고, 고친 것·남은 것(수정 버전 없음)·권장 완화 조치를 요약

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
