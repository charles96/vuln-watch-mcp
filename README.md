# vuln-watch-mcp

Claude Code나 Codex가 코딩 중에 **보안 취약점을 찾고, 수정 방법까지 받아서 직접 고칠 수 있게** 해 주는 MCP 서버입니다.

| 데이터 소스 | 용도 |
|---|---|
| [OSV.dev](https://osv.dev) | 패키지 이름과 버전으로 바로 조회하는 취약점 DB (GitHub Advisory, PyPA, Go, RustSec 등 통합, **악성 패키지** 포함) |
| [NVD CVE API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0) | CVE 상세, CVSS, CWE, 영향받는 제품·버전 범위(CPE), 패치 링크 |
| [CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | 실제로 악용되고 있는 취약점 (조치 기한, 랜섬웨어 악용 여부, 필수 조치) |
| [FIRST EPSS](https://www.first.org/epss/) | 앞으로 30일 안에 실제로 악용될 확률 |
| 패키지 레지스트리 | npm, PyPI, Go proxy, crates.io, RubyGems, Packagist, NuGet, Maven Central의 최신 버전, deprecated/yank 여부, 마지막 배포일 |

모두 무료이고, 필수로 받아야 하는 API 키가 없습니다.

---

## 빠른 시작

> 요구 사항: **Node.js 18 이상**

### 방법 A: npx로 바로 실행 (설치 없음)

별도 설치 없이 아래 "등록" 단계로 바로 넘어가면 됩니다. 실행할 때마다 GitHub에서 받아 옵니다(처음 한 번만 받고 이후에는 캐시를 씁니다).

```bash
npx -y github:charles96/vuln-watch-mcp   # 직접 실행해 보기 (stdio로 대기하면 정상, Ctrl+C로 종료)
```

> 최신 커밋을 받으려면 `github:charles96/vuln-watch-mcp#main`처럼 브랜치를 지정하거나 `npm cache clean --force`를 실행하세요.

### 방법 B: 클론해서 설치 (업데이트는 `git pull`)

```bash
git clone https://github.com/charles96/vuln-watch-mcp.git
cd vuln-watch-mcp
npm install
npm run smoke           # 도구 목록이 나오면 설치 완료
```

이후 등록할 때 쓰는 실행 경로는 `node <클론한 경로>/src/index.js`입니다.

---

## Claude Code에 등록

```bash
# 방법 A (npx)
claude mcp add vuln-watch --scope user -- npx -y github:charles96/vuln-watch-mcp

# 방법 B (클론)
claude mcp add vuln-watch --scope user -- node /절대경로/vuln-watch-mcp/src/index.js

# (선택) NVD API 키를 함께 넣을 때
claude mcp add vuln-watch --scope user -e NVD_API_KEY=발급받은키 -- npx -y github:charles96/vuln-watch-mcp
```

- `--scope user`: 모든 프로젝트에서 사용합니다. 현재 프로젝트에서만 쓰려면 `--scope project`를 지정하세요(`.mcp.json`이 생성되어 팀과 공유됩니다).
- 확인: `claude mcp list` 또는 Claude Code 안에서 `/mcp`를 실행합니다.
- Windows 네이티브(WSL이 아닌 환경)에서 npx를 쓰는 경우: `-- cmd /c npx -y github:charles96/vuln-watch-mcp`

## Codex에 등록

`~/.codex/config.toml`에 추가합니다.

```toml
[mcp_servers.vuln-watch]
command = "npx"
args = ["-y", "github:charles96/vuln-watch-mcp"]
# 클론 방식: command = "node", args = ["/절대경로/vuln-watch-mcp/src/index.js"]
# env = { NVD_API_KEY = "발급받은키" }   # 선택
startup_timeout_sec = 60   # npx가 처음 받아 오는 시간 포함
tool_timeout_sec = 300     # NVD 교차 확인을 쓰면 오래 걸릴 수 있습니다 (기본값 60초)
```

확인: `codex mcp list`

## NVD API 키 (선택)

의존성 스캔의 기본 데이터 소스는 OSV입니다. OSV는 키가 필요 없고 요청 한 번에 수백 개 패키지를 조회하므로 **키가 없어도 스캔은 빠릅니다.**
NVD 키가 있으면 아래가 달라집니다. [여기서 신청](https://nvd.nist.gov/developers/request-an-api-key)하면 메일로 받습니다.

| | NVD 요청 한도 | 스캔 기본 동작 (`sources: "auto"`) |
|---|---|---|
| 키 없음 | 30초당 5회 (요청당 약 6.5초 대기) | OSV만 사용 |
| 키 있음 | 30초당 50회 (요청당 약 0.7초 대기) | OSV + NVD CPE 교차 확인 (패키지 60개씩) |

`search_vulnerabilities`, `latest_ecosystem_vulnerabilities`, `get_vulnerability`는 NVD를 쓰므로 키가 있으면 더 빠릅니다.

---

## 사용 예시

에이전트에게 자연어로 요청하면 알맞은 도구를 골라 호출합니다.

- "이 프로젝트 의존성 보안 취약점 점검하고 고쳐줘"
- "axios 설치해도 괜찮아?" (최신 버전의 취약점, 악성 여부, deprecated 여부 확인)
- "최근 2주간 나온 Python 심각 취약점 알려줘"
- "CVE-2021-44228, 우리 log4j-core 2.14.1에서 어떻게 고쳐?"
- "GHSA-35jh-r3h4-6jhm 뭐야?"
- Claude Code에서 `/mcp__vuln-watch__security_audit`: 스캔 → 최신 취약점 확인 → 수정 → 재검증을 한 번에 진행합니다.

## 지원하는 의존성 파일

`scan_project_dependencies`가 읽는 파일입니다. 같은 폴더에 lockfile이 있으면 lockfile을 우선합니다. `recursive: true`로 하위 폴더(모노레포)까지 찾습니다.

| 언어 | 파일 |
|---|---|
| JavaScript/TypeScript | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (v1, berry), `pnpm-lock.yaml` (v5~v9), `package.json` |
| Python | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements*.txt` |
| Go | `go.mod` |
| Rust | `Cargo.lock` |
| PHP | `composer.lock` |
| Ruby | `Gemfile.lock` |
| Java/Kotlin | `gradle.lockfile`, `pom.xml` (`${property}` 치환), `build.gradle`, `build.gradle.kts` |
| .NET | `packages.lock.json`, `*.csproj`/`*.fsproj`/`*.vbproj`, `Directory.Packages.props` |

## 도구

| 분류 | 도구 | 한 줄 설명 |
|---|---|---|
| 내 프로젝트 점검 | [`scan_project_dependencies`](#scan_project_dependencies) | 프로젝트 의존성 전체 스캔 + 조치 계획 + 패키지 상태 |
| | [`check_package`](#check_package) | 패키지 하나 점검 (설치 전 확인용, 버전 생략 시 최신 버전) |
| 최신 취약점 파악 | [`latest_ecosystem_vulnerabilities`](#latest_ecosystem_vulnerabilities) | 언어/생태계별 최신 CVE |
| | [`search_vulnerabilities`](#search_vulnerabilities) | NVD 키워드 검색 |
| 특정 취약점 조사 | [`get_vulnerability`](#get_vulnerability) | CVE/GHSA/PYSEC 등 ID 하나의 전체 정보와 패키지별 수정 버전 |
| 실제 악용 여부 | [`check_kev`](#check_kev) | CVE 목록의 KEV 등재 여부 + EPSS |
| | [`search_kev`](#search_kev) | KEV 카탈로그 검색 |

공통 사항:
- **우선순위:** 🚨 악성 패키지 → 🔥 KEV(실제 악용) → ⚠️ EPSS 10% 이상 → CRITICAL/HIGH → 최신순
- **심각도 값:** `min_severity`에는 `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`을 넣습니다.
- **생태계 값:** `ecosystem`에는 `npm`(`javascript`, `typescript`, `node`), `pypi`(`python`), `go`, `maven`(`java`, `kotlin`), `composer`(`php`), `rubygems`(`ruby`), `cargo`(`rust`), `nuget`(`dotnet`)을 쓸 수 있습니다. 괄호 안은 같은 뜻으로 받는 별칭입니다.
- **데이터 소스 선택:** `sources`에는 `auto`(기본: OSV, 키가 있으면 NVD 교차 확인 추가), `osv`, `nvd`, `both`를 쓸 수 있습니다.
- **결과 형식:** `check_kev`를 뺀 모든 도구는 `format: "json"`으로 구조화된 결과를 받을 수 있습니다 (기본값 `markdown`).

### `scan_project_dependencies`

프로젝트의 의존성 파일을 읽어 설치된 버전마다 알려진 취약점을 찾습니다. OSV로 모든 패키지를 한 번에 조회하고, 결과에 KEV·EPSS·레지스트리 정보를 붙입니다. 결과는 세 부분입니다.

1. **조치 계획:** 패키지별로 고칠 순서, 목표 버전, 실행할 명령
   - 목표 버전 자체에 남은 취약점이 없는지 OSV로 다시 확인하고, 남아 있으면 깨끗한 버전이 나올 때까지 올립니다.
   - 최신 버전과 그 버전의 취약점 여부, deprecated/유지보수 중단 경고, 메이저 업그레이드 경고, 간접 의존성 고정 방법도 함께 보여 줍니다.
   - 악성 패키지는 "업그레이드하지 말고 제거 + 비밀값 교체"로 안내합니다.
2. **패키지 상태:** 취약점은 없지만 deprecated, yank, 2년 이상 배포 없음에 해당하는 직접 의존성
3. **상세 결과:** 우선순위 상위 N건은 자세히, 나머지는 한 줄 요약 (출력이 너무 커지지 않도록)

| 파라미터 | 필수 | 기본값 | 설명 |
|---|---|---|---|
| `path` | ✅ | | 프로젝트 루트 폴더 또는 의존성 파일 경로 |
| `recursive` | | `false` | 하위 폴더까지 스캔 (깊이 4, `node_modules`·`vendor`·빌드 결과·가상환경 제외) |
| `include_dev` | | `false` | dev/test 의존성 포함 |
| `include_transitive` | | `true` | lockfile의 간접 의존성 포함 |
| `sources` | | `auto` | 데이터 소스 선택 |
| `max_packages` | | 키 없음 10 / 키 있음 60 | 이번 호출에서 **NVD 교차 확인**할 패키지 수 (OSV는 항상 전체) |
| `offset` | | `0` | NVD 교차 확인을 이어서 할 시작 위치 (OSV 결과는 `offset=0` 호출에만 나옴) |
| `check_health` | | `true` | 직접 의존성의 deprecated/yank/유지보수 중단 확인 |
| `min_severity` | | | 이 심각도 미만 숨김 (악성·KEV는 항상 표시) |
| `detailed_findings` | | `15` | 자세히 보여 줄 상위 결과 수 (조치 계획은 항상 전체) |

```json
{ "path": "/home/me/my-app", "recursive": true, "min_severity": "HIGH" }
```

### `check_package`

패키지 하나를 점검합니다. **새 패키지를 설치하거나 버전을 올리기 전에** 쓰는 용도입니다.
- `version`을 생략하면 레지스트리의 최신 버전을 점검합니다.
- 악성 패키지, deprecated, yank, 유지보수 중단 여부를 함께 알려 줍니다.
- 레지스트리에 없는 이름이면 타이포스쿼팅 위험을 경고합니다.
- `ecosystem` 없이 제품 이름(nginx, openssl 등)만 주면 NVD로 찾습니다.

| 파라미터 | 필수 | 기본값 | 설명 |
|---|---|---|---|
| `name` | ✅ | | 패키지/제품 이름. 예: `lodash`, `@babel/traverse`, `django`, `github.com/gin-gonic/gin`, `org.apache.logging.log4j:log4j-core`(Maven), `guzzlehttp/guzzle`(Composer), `nginx` |
| `version` | | 최신 버전 | 점검할 버전 (생략하려면 `ecosystem` 필요) |
| `ecosystem` | | | 생태계. 지정하면 OSV로 정확히 매칭하고 업그레이드 명령을 만들어 줍니다. |
| `vendor` | | | NVD 결과를 좁힐 CPE 벤더 이름. 예: `djangoproject`, `f5`, `openssl` |
| `sources` | | `auto` | 데이터 소스 선택 |
| `min_severity` | | | 이 심각도 미만 숨김 |

```json
{ "name": "axios", "ecosystem": "npm" }
```

### `latest_ecosystem_vulnerabilities`

특정 언어/생태계에서 최근 공개된 CVE를 최신순으로 보여 줍니다(EPSS 포함). NVD의 플랫폼 정보(CPE)로 찾은 결과에 키워드 검색 결과를 합쳐, NVD가 아직 분석하지 않은 신규 CVE도 포함합니다.

| 파라미터 | 필수 | 기본값 | 설명 |
|---|---|---|---|
| `ecosystem` | ✅ | | 생태계 |
| `days` | | `30` | 최근 N일 (1~120, NVD 제한) |
| `keyword` | | | 추가로 좁힐 키워드. 예: `express`, `deserialization` |
| `min_severity` | | | 이 심각도 미만 숨김 |
| `kev_only` | | `false` | KEV에 등재된 것만 |
| `limit` | | `20` | 최대 결과 수 (1~100) |

```json
{ "ecosystem": "python", "days": 14, "min_severity": "HIGH" }
```

### `search_vulnerabilities`

NVD CVE 설명문을 키워드로 검색합니다(최신순, 여러 단어는 모두 포함된 것만, EPSS 포함). 라이브러리, 프레임워크, 취약점 유형으로 찾을 때 씁니다.

| 파라미터 | 필수 | 기본값 | 설명 |
|---|---|---|---|
| `keyword` | ✅ | | 검색어. 예: `next.js middleware`, `prototype pollution`, `log4j` |
| `ecosystem` | | | 다른 플랫폼 대상 CVE 제외 |
| `days` | | | 최근 N일 안에 공개된 것만 (1~120) |
| `cwe` | | | CWE로 거르기. 예: `CWE-79` |
| `min_severity` | | | 이 심각도 미만 숨김 |
| `kev_only` | | `false` | KEV에 등재된 것만 |
| `exact_match` | | `false` | 검색어를 정확한 구문으로 취급 |
| `limit` | | `15` | 최대 결과 수 (1~100) |

```json
{ "keyword": "next.js", "ecosystem": "npm", "days": 60 }
```

### `get_vulnerability`

취약점 하나의 전체 정보를 보여 줍니다. 로그, `npm audit`/`pip-audit` 결과, 보안 공지에 ID가 나왔을 때 씁니다.
- **받는 ID:** CVE, GHSA, PYSEC, GO, RUSTSEC, MAL
- **ID 연결:** CVE와 GHSA를 서로 따라가 NVD와 OSV 정보를 합칩니다.
- **`installed_version`을 주면:** 그 버전 기준으로 올려야 할 버전을 계산합니다.
- **결과:** 설명, CVSS, EPSS, CWE와 코드 수정 가이드, **패키지별 영향 범위와 수정 버전(OSV)**, 영향받는 제품(NVD, 요청한 패키지 우선, 최대 25개), KEV 정보, 패치/권고 링크(최대 30개)

| 파라미터 | 필수 | 기본값 | 설명 |
|---|---|---|---|
| `id` | ✅ | | 예: `CVE-2021-44228`, `GHSA-35jh-r3h4-6jhm`, `PYSEC-2021-19` |
| `installed_version` | | | 사용 중인 버전 (수정 버전 계산용) |
| `package` | | | 여러 패키지가 걸린 경우 내가 쓰는 패키지 이름. Maven은 `log4j-core`처럼 artifact 이름만 줘도 됩니다. |
| `ecosystem` | | | 생태계 (업그레이드 명령 생성용) |

```json
{ "id": "CVE-2021-44228", "installed_version": "2.14.1", "package": "log4j-core", "ecosystem": "maven" }
```

### `check_kev`

CVE 목록이 CISA KEV(실제로 악용되고 있는 취약점 목록)에 있는지 한 번에 확인합니다. 내려받아 둔 카탈로그에서 조회하므로 빠릅니다.
- 등재된 CVE는 조치 기한, 랜섬웨어 악용 여부, CISA 필수 조치를 보여 줍니다.
- 모든 CVE에 EPSS 점수를 붙입니다.

| 파라미터 | 필수 | 기본값 | 설명 |
|---|---|---|---|
| `cve_ids` | ✅ | | CVE ID 배열 (1~500개) |

```json
{ "cve_ids": ["CVE-2021-44228", "CVE-2020-8203"] }
```

### `search_kev`

KEV 카탈로그를 직접 검색합니다(최근 추가순). "최근 한 달간 새로 악용되기 시작한 취약점" 같은 질문에 씁니다.

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

1. `scan_project_dependencies`(recursive)로 의존성 전체 스캔
2. 감지된 생태계마다 `latest_ecosystem_vulnerabilities`로 최근 30일 취약점 확인
3. 악성 패키지 제거 → KEV → EPSS 높음 → CRITICAL → HIGH 순으로 수정
   - 의존성 파일과 lockfile을 업데이트하고, 간접 의존성은 overrides/resolutions로 고정합니다.
   - 코드에서 취약한 기능을 쓰는 곳을 찾아 CWE 가이드대로 수정합니다.
   - deprecated나 유지보수가 중단된 패키지는 교체합니다.
4. 다시 스캔해서 확인하고, 고친 것·남은 것·권장 완화 조치를 요약

## 결과에 포함되는 정보

| 항목 | 내용 |
|---|---|
| 우선순위 | 🚨 악성 → 🔥 KEV → ⚠️ EPSS 10% 이상 → CRITICAL/HIGH → 최신순 |
| 수정 버전 | OSV의 패키지별 수정 버전을 우선 사용합니다. NVD만 있으면 버전 범위 상한을 쓰고, CVE 설명의 "fixed in X"와 비교해 더 높은 쪽을 권장합니다. |
| 검증된 목표 버전 | 목표 버전에 남은 취약점이 없는지 OSV로 다시 확인합니다. 남아 있으면 실제로 배포된 버전 중에서 깨끗한 버전이 나올 때까지 올립니다. |
| 최신 버전 | 레지스트리 최신 버전, 배포일, 그 버전의 취약점 여부 |
| 업그레이드 명령 | `npm install x@y`, `pip install "x>=y"`, `go get x@vY`, `cargo update -p`, `composer require`, `bundle update`, `dotnet add package` 등 |
| 간접 의존성 | `npm ls`, `overrides`/`resolutions`/`pnpm.overrides`, constraints로 고정하는 방법 |
| 패키지 상태 | deprecated, yank, 2년 이상 배포 없음, npm 보안 자리표시자(악성 패키지 삭제 흔적) |
| 메이저 업그레이드 경고 | 호환성이 깨지는 변경이 있을 수 있으면 경고 |
| 코드 수정 가이드 | CWE별 코드 수준 수정 방법 (예: CWE-1321 프로토타입 오염 → `__proto__` 키 차단) |
| KEV / EPSS | 등재일, CISA 조치 기한, 랜섬웨어 악용 여부, 필수 조치 / 30일 내 악용 확률과 백분위 |
| ID 연결 | CVE ↔ GHSA/PYSEC/GO/RUSTSEC를 묶어 중복 없이 하나로 보여 줍니다. |
| 참고 링크 | 패치 커밋, 권고문, GHSA를 우선 표시 |

---

## 저장소 구조

```
vuln-watch-mcp/
├── src/
│   ├── index.js         # MCP 서버 진입점: 도구 7개, security_audit 프롬프트, 서버 안내문
│   ├── scan.js          # 분석 파이프라인: OSV+NVD 병합, KEV/EPSS 부착, 조치 계획, 목표 버전 검증, 패키지 상태
│   ├── deps.js          # 의존성 파일 파서 (8개 생태계, 20여 종 파일), 하위 폴더 탐색
│   ├── osv.js           # OSV.dev 클라이언트 (일괄 조회, 상세 조회, 중복 권고 묶기)
│   ├── nvd.js           # NVD API 클라이언트 (속도 제한, 재시도, 캐시), CVSS/CPE 파싱, 버전 비교
│   ├── kev.js           # CISA KEV 카탈로그 다운로드, 캐시, 검색
│   ├── epss.js          # FIRST EPSS 일괄 조회
│   ├── registry.js      # 8개 패키지 레지스트리 조회 (최신 버전, deprecated, yank, 배포일)
│   ├── report.js        # 결과 생성: 수정 버전 계산, 업그레이드 명령, 정렬, Markdown 출력
│   ├── cvss.js          # CVSS 3.x 벡터로 점수 계산 (OSV는 벡터만 제공)
│   ├── ecosystems.js    # 언어별 설정 (CPE 플랫폼, 검색 키워드, 업그레이드 명령 템플릿)
│   ├── remediation.js   # CWE별 코드 수정 가이드
│   └── cache.js         # 메모리 + 디스크 캐시 (오프라인이면 만료된 캐시 사용)
├── scripts/
│   └── smoke.js         # stdio로 서버를 띄워 도구를 호출하는 테스트 클라이언트
├── examples/
│   ├── vulnerable-node/     # npm 샘플 (lodash, minimist, jsonwebtoken)
│   ├── vulnerable-python/   # Python 샘플 (django, requests)
│   └── multi-ecosystem/     # 8개 생태계 lockfile 샘플 (악성 패키지, KEV 취약점 포함)
├── package.json
└── README.md
```

## 테스트

```bash
npm run smoke                                         # 도구와 프롬프트 목록
node scripts/smoke.js scan_project_dependencies '{"path":"examples/multi-ecosystem","recursive":true}'
node scripts/smoke.js check_package '{"name":"flatmap-stream","version":"0.1.1","ecosystem":"npm"}'
node scripts/smoke.js get_vulnerability '{"id":"GHSA-35jh-r3h4-6jhm","installed_version":"4.17.15","package":"lodash","ecosystem":"npm"}'
node scripts/smoke.js latest_ecosystem_vulnerabilities '{"ecosystem":"npm","days":14}'
```

## 환경 변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `NVD_API_KEY` | (없음) | NVD API 키 (선택) |
| `KEV_TTL_HOURS` | 6 | KEV 카탈로그 캐시 유지 시간 |
| `NVD_TTL_HOURS` | 12 | NVD 응답 캐시 유지 시간 |
| `OSV_TTL_HOURS` | 6 | OSV 응답 캐시 유지 시간 |
| `VULN_WATCH_CACHE_DIR` | `~/.cache/vuln-watch-mcp` | 디스크 캐시 위치 |

EPSS는 24시간, 레지스트리 정보는 6시간 동안 캐시합니다.

## 문제 해결

| 증상 | 조치 |
|---|---|
| 도구가 보이지 않음 | 등록 후 Claude Code나 Codex를 재시작하고 `/mcp`(Claude Code) 또는 `codex mcp list`로 상태를 확인하세요. |
| Codex에서 서버 시작이 타임아웃됨 | npx가 처음 패키지를 받는 시간 때문입니다. `startup_timeout_sec`를 늘리거나 클론 방식을 쓰세요. |
| Codex에서 스캔이 타임아웃됨 | `sources: "osv"`로 스캔하거나 `tool_timeout_sec`를 늘리세요. NVD 교차 확인이 느린 경우 `NVD_API_KEY`를 설정하면 빨라집니다. |
| `NVD HTTP 403/429` | NVD 요청 한도 초과입니다. 자동으로 재시도하지만, 계속되면 API 키를 설정하세요. |
| 결과가 예전 그대로임 | 캐시 때문입니다. `~/.cache/vuln-watch-mcp`를 지우면 새로 조회합니다. |

## 한계

- **lockfile이 없으면 버전이 부정확합니다.** `package.json`, `build.gradle`, `*.csproj`처럼 범위로 적힌 파일만 있으면 `^1.2.3`을 최소 버전(`1.2.3`)으로 간주하므로 오탐이 생길 수 있습니다. 간접 의존성은 lockfile이 있어야 보입니다.
- **`pom.xml`은 부분적으로만 해석합니다.** 직접 선언된 의존성과 `${property}` 치환만 처리하고, 부모 POM이나 BOM으로 관리되는 버전은 해석하지 못합니다. 정확한 결과가 필요하면 `gradle.lockfile`을 쓰거나 `mvn dependency:list` 결과를 참고하세요.
- **NVD 매칭(`sources: nvd`/`both`)은 이름 추측에 의존합니다.** 패키지 이름을 CPE 제품 이름으로 바꿔 찾기 때문에 `Match confidence: medium` 결과는 같은 프로젝트인지 직접 확인해야 합니다. OSV(기본값)는 패키지 이름으로 바로 조회하므로 이 문제가 없습니다.
- **신규 CVE의 상세 정보가 늦게 붙습니다.** NVD가 아직 분석하지 않은(`Awaiting Analysis`) CVE는 점수나 영향 범위가 비어 있을 수 있습니다. OSV에 GitHub 권고가 있으면 그쪽 정보로 보완됩니다.
- **목표 버전 검증은 OSV 기준입니다.** OSV에 없는 취약점까지 없다는 보장은 아닙니다.
- **컨테이너 이미지, OS 패키지, 소스 코드 자체의 취약점(SAST)은 범위 밖입니다.**
